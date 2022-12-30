# Copyright 2016-2018 Ildar Nasyrov <https://it-projects.info/team/iledarn>
# Copyright 2016-2018,2021 Ivan Yelizariev <https://twitter.com/yelizariev>
# Copyright 2019 Alexandr Kolushov <https://it-projects.info/team/KolushovAlexandr>
# Copyright 2019 Rafis Bikbov <https://it-projects.info/team/RafiZz>
# Copyright 2019 Dinar Gabbasov <https://it-projects.info/team/GabbasovDinar>
# Copyright 2019-2020 Eugene Molotov <https://it-projects.info/team/em230418>
# License MIT (https://opensource.org/licenses/MIT).

import logging

from odoo import _, models
from odoo.exceptions import MissingError, UserError
from odoo.tools.safe_eval import safe_eval
from botocore.exceptions import ClientError
import base64
from .res_config_settings import NotAllCredentialsGiven

_logger = logging.getLogger(__name__)

PREFIX = "s3://"


def is_s3_bucket(bucket):
    meta = getattr(bucket, "meta", None)
    return meta and getattr(meta, "service_name", None) == "s3"


class IrAttachment(models.Model):

    _inherit = "ir.attachment"

    def _filter_protected_attachments(self):
        return self.filtered(
            lambda r: r.res_model not in ["ir.ui.view", "ir.ui.menu"]
                      and not r.name.startswith("/web/content/")
                      and not r.name.startswith("/web/static/")
        )

    def _get_datas_related_values_with_bucket(
            self, bucket, data, filename, mimetype, checksum=None
    ):
        bin_data = base64.b64decode(data) if data else b""
        if not checksum:
            checksum = self._compute_checksum(bin_data)
        fname, url = self._file_write_with_bucket(
            bucket, bin_data, filename, mimetype, checksum
        )
        return {
            "file_size": len(bin_data),
            "checksum": checksum,
            "index_content": self._index(bin_data, mimetype),
            "store_fname": fname,
            "db_datas": False,
            "type": "binary",
            "url": url,
        }

    def _write_records_with_bucket(self, bucket):
        _logger.info("evt=UPLOAD_TO_S3 msg=_write_records_with_bucket bucket=" + str(bucket))
        for attach in self:
            vals = self._get_datas_related_values_with_bucket(
                bucket, attach.datas, attach.name, attach.mimetype
            )
            super(IrAttachment, attach.sudo()).write(vals)

    def _inverse_datas(self):
        condition = self.env["res.config.settings"]._get_s3_settings(
            "s3.condition", "S3_CONDITION"
        )
        _logger.info("evt=UPLOAD_TO_S3 msg=_inverse_datas condition=" + str(condition))
        if condition and not self.env.context.get("force_s3"):
            condition = safe_eval(condition, mode="eval")
            s3_records = self.sudo().search([("id", "in", self.ids)] + condition)
        else:
            # if there is no condition or force_s3 in context
            # then store all attachments on s3
            s3_records = self

        _logger.info("evt=UPLOAD_TO_S3 msg=s3_records s3_records=" + str(s3_records))

        if s3_records:

            try:
                bucket = self.env["res.config.settings"].get_s3_bucket()
            except NotAllCredentialsGiven:
                _logger.info("evt=UPLOAD_TO_S3 msg=something wrong on aws side, keep attachments as usual")
                s3_records = self.env[self._name]
            except Exception:
                _logger.exception(
                    "evt=UPLOAD_TO_S3 msg=Something bad happened with S3. Keeping attachments as usual"
                )
                s3_records = self.env[self._name]
            else:
                s3_records = s3_records._filter_protected_attachments()
                s3_records = s3_records.filtered(lambda r: r.type != "url")
                s3_records._write_records_with_bucket(bucket)

        return super(IrAttachment, self - s3_records)._inverse_datas()

    def _file_read(self, fname):
        if not fname.startswith(PREFIX):
            return super(IrAttachment, self)._file_read(fname)

        bucket = self.env["res.config.settings"].get_s3_bucket()

        file_id = fname[len(PREFIX) :]
        _logger.info("evt=UPLOAD_TO_S3 msg=reading file with id {}".format(file_id))

        obj = bucket.Object(file_id)
        data = obj.get()
        return data["Body"].read()

    def _file_write(self, bin_value, checksum):
        storage = self._storage()
        try:
            bucket = self.env["res.config.settings"].get_s3_bucket()
            fname = "odoo/{}".format(checksum)

            bucket.put_object(
                Key=fname,
                Body=bin_value,
                ACL="public-read",
                ContentDisposition='attachment; filename="%s"' % fname,
            )

            _logger.info("evt=UPLOAD_TO_S3 msg=uploaded file with id {}".format(fname))

            obj_url = self.env["res.config.settings"].get_s3_obj_url(bucket, fname)

            self._mark_for_gc(fname)
            return PREFIX + fname
        except IOError:
            _logger.info("evt=UPLOAD_TO_S3 msg=Error uploading file to s3. Falling back to local")
            return super(IrAttachment, self)._file_write(bin_value, checksum)




    def _file_delete(self, fname):
        if not fname.startswith(PREFIX):
            return super(IrAttachment, self)._file_delete(fname)

        bucket = self.env["res.config.settings"].get_s3_bucket()

        file_id = fname[len(PREFIX) :]
        _logger.debug("deleting file with id {}".format(file_id))

        obj = bucket.Object(file_id)
        obj.delete()

    def _force_storage_with_bucket(self, bucket, domain):
        attachment_ids = self._search(domain)

        _logger.info(
            "evt=UPLOAD_TO_S3 msg=Approximately %s attachments to store to %s"
            % (len(attachment_ids), repr(bucket))
        )
        for attach in map(self.browse, attachment_ids):
            is_protected = not bool(attach._filter_protected_attachments())

            if is_protected:
                _logger.info("evt=UPLOAD_TO_S3 msg=ignoring protected attachment %s", repr(attach))
                continue
            else:
                _logger.info("evt=UPLOAD_TO_S3 msg=storing %s", repr(attach))

            old_store_fname = attach.store_fname
            data = self._file_read(old_store_fname)
            bin_data = base64.b64decode(data) if data else b""
            checksum = (
                self._compute_checksum(bin_data)
                if not attach.checksum
                else attach.checksum
            )

            new_store_fname, url = self._file_write_with_bucket(
                bucket, bin_data, attach.name, attach.mimetype, checksum
            )
            attach.write({"store_fname": new_store_fname, "url": url})
            self._file_delete(old_store_fname)

    def force_storage_s3(self):
        try:
            bucket = self.env["res.config.settings"].get_s3_bucket()
        except NotAllCredentialsGiven:
            if self.env.context.get("module") == "general_settings":
                raise MissingError(
                    _(
                        "Some of the S3 connection credentials are missing.\n Don't forget to click the ``[Save]`` button after any changes you've made"
                    )
                )
            else:
                raise

        s3_condition = self.env["ir.config_parameter"].sudo().get_param("s3.condition")
        condition = s3_condition and safe_eval(s3_condition, mode="eval") or []

        return self._force_storage_with_bucket(
            bucket,
            [
                ("type", "!=", "url"),
                ("id", "!=", 0),
                ("store_fname", "not ilike", PREFIX),
                ("store_fname", "!=", False),
                ("res_model", "not in", ["ir.ui.view", "ir.ui.menu"]),
            ]
            + condition,
        )

    def _set_where_to_store(self, vals_list):
        bucket = None
        try:
            bucket = self.env["res.config.settings"].get_s3_bucket()
        except NotAllCredentialsGiven:
            _logger.info("evt=UPLOAD_TO_S3 msg=Could not get S3 bucket. Not all credentials given")
        except Exception:
            _logger.exception("evt=UPLOAD_TO_S3 msg=Could not get S3 bucket")

        if not bucket:
            return super(IrAttachment, self)._set_where_to_store(vals_list)

        # TODO: тут игнорируется s3 condition и соотвествующий bucket пишется везде
        for values in vals_list:
            values["_bucket"] = bucket

        return super(IrAttachment, self)._set_where_to_store(vals_list)

    def _file_write_with_bucket(self, bucket, bin_data, filename, mimetype, checksum):
        # make sure, that given bucket is s3 bucket
        if not is_s3_bucket(bucket):
            return super(IrAttachment, self)._file_write_with_bucket(
                bucket, bin_data, filename, mimetype, checksum
            )

        file_id = "odoo/{}".format(checksum)
        try:
            bucket.put_object(
                Key=file_id,
                Body=bin_data,
                ACL="public-read",
                ContentType=mimetype,
                ContentDisposition='attachment; filename="%s"' % filename,
            )

            _logger.debug("evt=UPLOAD_TO_S3 msg=uploaded file with id {}".format(file_id))
            obj_url = self.env["res.config.settings"].get_s3_obj_url(bucket, file_id)
            return PREFIX + file_id, obj_url
        except ClientError as e:
            raise UserError(_(e) + ". This happened while trying to upload attachment to S3")
