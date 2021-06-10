# Default imports
# None

# Custom imports
# None


class DynamicsError(Exception):
    def __init__(
        self,
        message=None,
        raw_message=None,
        response_url=None,
        context=None,
    ):
        super(DynamicsError, self).__init__(message)
        self.message = message
        self.raw_message = raw_message
        self.context = context
        self.response_url = response_url

    def to_json(self):
        response = {
            "message": self.message,
            "raw_message": self.raw_message,
            "response_url": self.response_url,
            "context": self.context,
        }
        try:
            response["status_code"] = self.status_code
        except AttributeError:
            response["status_code"] = None
        finally:
            return response


class BadRequestError(DynamicsError):
    status_code = 400


class UnauthorizedError(DynamicsError):
    status_code = 401


class ForbiddenError(DynamicsError):
    status_code = 403


class NotFoundError(DynamicsError):
    status_code = 404


class PreconditionFailedError(DynamicsError):
    status_code = 412


class PayloadTooLargeError(DynamicsError):
    status_code = 413


class TooManyRequestsError(DynamicsError):
    status_code = 429


class InternalServerError(DynamicsError):
    status_code = 500


class NotImplementedError(DynamicsError):
    status_code = 501


class ServiceUnavailableError(DynamicsError):
    status_code = 503
