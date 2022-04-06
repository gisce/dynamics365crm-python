# Default imports
import requests
import logging

# Custom imports
from .errors import (
    BadRequestError,
    UnauthorizedError,
    ForbiddenError,
    NotFoundError,
    PreconditionFailedError,
    PayloadTooLargeError,
    TooManyRequestsError,
    InternalServerError,
    NotImplementedError,
    ServiceUnavailableError,
)


class Client:
    api_base_url = "api/data/v9.0"
    header = {
        "Accept": "application/json, */*",
        "Content-Type": "application/json; charset=utf-8",
        "OData-MaxVersion": "4.0",
        "OData-Version": "4.0",
        "Prefer": "return=representation",
    }

    def __init__(self, resource, client_id=None, client_secret=None, token=None):
        self.resource = resource
        self.client_id = client_id
        self.client_secret = client_secret
        self.token = token

    def make_request(
        self,
        method,
        endpoint,
        expand=None,
        filter=None,
        orderby=None,
        select=None,
        skip=None,
        top=None,
        data=None,
        json=None,
        **kwargs
    ):
        """
        this method do the request petition, receive the different methods (post, delete, patch, get) that the api allow, see the documentation to check how to use the filters
        https://msdn.microsoft.com/en-us/library/gg309461(v=crm.7).aspx
        :param method:
        :param endpoint:
        :param expand:
        :param filter:
        :param orderby:
        :param select:
        :param skip:
        :param top:
        :param data:
        :param json:
        :param kwargs:
        :return:
        """
        extra = {}
        if expand is not None and isinstance(expand, str):
            extra["$expand"] = str(expand)
        if filter is not None and isinstance(filter, str):
            extra["$filter"] = filter
        if orderby is not None and isinstance(orderby, str):
            extra["$orderby"] = orderby
        if select is not None and isinstance(select, str):
            extra["$select"] = select
        if skip is not None and isinstance(skip, str):
            extra["$skip"] = skip
        if top is not None and isinstance(top, str):
            extra["$top"] = str(top)
        extra = "&".join(["{0}={1}".format(k, v) for k, v in extra.items()])
        if self.resource != "":
            if self.token:
                self.header["Authorization"] = "Bearer " + self.token
                url = "{0}{1}/{2}?{3}".format(
                    self.resource, self.api_base_url, endpoint, extra
                )
                if method == "get":
                    response = requests.request(
                        method, url, headers=self.header, params=kwargs
                    )
                elif method == "patch":
                    patch_headers = self.header.copy()
                    patch_headers.update({
                        "If-Match": "*",
                        "Content-Type": kwargs.get(
                            "content_type", "application/json; charset=utf-8"
                        )
                    })
                    response = requests.request(
                        method,
                        url,
                        headers=patch_headers,
                        data=data,
                        json=json
                    )
                else:
                    post_headers = self.header.copy()
                    post_headers.update({
                        "Content-Type": kwargs.get(
                            "content_type", "application/json; charset=utf-8"
                        )
                    })
                    response = requests.request(
                        method,
                        url,
                        headers=post_headers,
                        data=data,
                        json=json
                    )
                return response if "$batch" in url else self.parse_response(response)
            else:
                raise Exception("To make petitions the token is necessary")

    def _get(self, endpoint, data=None, **kwargs):
        return self.make_request("get", endpoint, data=data, **kwargs)

    def _post(self, endpoint, data=None, json=None, **kwargs):
        return self.make_request("post", endpoint, data=data, json=json, **kwargs)

    def _delete(self, endpoint, **kwargs):
        return self.make_request("delete", endpoint, **kwargs)

    def _patch(self, endpoint, data=None, json=None, **kwargs):
        return self.make_request("patch", endpoint, data=data, json=json, **kwargs)

    def parse_response(self, response):
        """
        This method get the response request and returns json data or raise exceptions
        :param response:
        :return:
        """
        response_url = response.url
        status_code = response.status_code
        raw_message = response.text

        if status_code == 204:
            return True
        elif status_code == 400:
            raise BadRequestError(
                "The URL {response_url} retrieved an {status_code} error. Please check your request body and try again".format(**locals()),
                raw_message,
                response_url,
            )
        elif status_code == 401:
            raise UnauthorizedError(
                "The URL {response_url} retrieved and {status_code} error. Please check your credentials, make sure you have permission to perform this action and try again.".format(**locals()),
                raw_message,
                response_url,
            )
        elif status_code == 403:
            raise ForbiddenError(
                "The URL {response_url} retrieved and {status_code} error. Please check your credentials, make sure you have permission to perform this action and try again.".format(**locals()),
                raw_message,
                response_url,
            )
        elif status_code == 404:
            raise NotFoundError(
                "The URL {response_url} retrieved an {status_code} error. Please check the URL and try again.".format(**locals()),
                raw_message,
                response_url,
            )
        elif status_code == 412:
            raise PreconditionFailedError(
                "The URL {response_url} retrieved an {status_code} error. Please check the URL and try again.".format(**locals()),
                raw_message,
                response_url,
            )
        elif status_code == 413:
            raise PayloadTooLargeError(
                "The URL {response_url} retrieved an {status_code} error. Please check the URL and try again.".format(**locals()),
                raw_message,
                response_url,
            )

        elif status_code == 429:
            raise TooManyRequestsError(
                "The URL {response_url} retrieved an {status_code} error. Please check the URL and try again.".format(**locals()),
                raw_message,
                response_url,
            )
        elif status_code == 500:
            raise InternalServerError(
                "The URL {response_url} retrieved an {status_code} error. Please check the URL and try again.".format(**locals()),
                raw_message,
                response_url,
            )

        elif status_code == 501:
            raise NotImplementedError(
                "The URL {response_url} retrieved an {status_code} error. Please check the URL and try again.".format(**locals()),
                raw_message,
                response_url,
            )

        elif status_code == 503:
            raise ServiceUnavailableError(
                "The URL {response_url} retrieved an {status_code} error. Please check the URL and try again.".format(**locals()),
                raw_message,
                response_url,
            )
        return response.json()

    def url_petition(self, redirect_uri):
        if (
            self.client_id is not None
            and redirect_uri is not None
            and self.resource is not None
        ):
            url = "https://login.microsoftonline.com/{0}/oauth2/authorize?client_id={1}&response_type={2}&redirect_uri={3}&response_mode={4}&resource={5}".format(
                "common", self.client_id, "code", redirect_uri, "query", self.resource
            )
            return url
        else:
            raise Exception(
                "The attributes necessary to get the url were not obtained."
            )

    def exchange_code(self, redirect_uri, code):
        if (
            self.client_id is not None
            and self.client_secret is not None
            and redirect_uri is not None
            and code is not None
        ):
            url = "https://login.microsoftonline.com/common/oauth2/token"
            args = {
                "client_id": self.client_id,
                "redirect_uri": redirect_uri,
                "client_secret": self.client_secret,
                "code": code,
                "grant_type": "authorization_code",
            }
            response = requests.post(url, data=args)
            return self.parse_response(response)
        else:
            raise Exception(
                "The attributes necessary to exchange the code were not obtained."
            )

    def refresh_token(self, refresh_token, redirect_uri):
        if (
            self.client_id is not None
            and self.client_secret is not None
            and refresh_token is not None
            and redirect_uri is not None
            and self.resource is not None
        ):
            url = "https://login.microsoftonline.com/common/oauth2/token"
            args = {
                "client_id": self.client_id,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "redirect_uri": redirect_uri,
                "client_secret": self.client_secret,
                "resource": self.resource,
            }
            response = requests.post(url, data=args)
            return self.parse_response(response)
        else:
            raise Exception(
                "The attributes necessary to refresh the token were not obtained."
            )

    def set_token(self, token):
        """
        Sets the Token for its use in this library.
        :param token: A string with the Token.
        :return:
        """
        if token != "":
            self.token = token

    # TODO: four main methods (CRUD)
    def get_data(self, type, **kwargs):
        if type is not None:
            return self._get(type, **kwargs)
        raise Exception("Missing param `type` when retrieving data.")

    def create_data(self, type, data, **kwargs):
        if type is not None and data is not None:
            return self._post(type, json=data, **kwargs)
        raise Exception("Missing params `type` or `data` when creating data.")

    def update_data(self, type, id, data, **kwargs):
        if type is not None and id is not None and data is not None:
            url = "{0}({1})".format(type, id)
            return self._patch(url, json=data, **kwargs)
        raise Exception("Missing params `type`, `id` or `data` when updating data.")

    def delete_data(self, type, id):
        if type is not None and id is not None:
            return self._delete("{0}({1})".format(type, id))
        raise Exception("Missing param `type` or `id` when deleting data.")

    def get_or_create_data(self, data_type, data, filter=None, **kwargs):
        """
        Parameters:
        ----------
        data_type           :   str
                                The type of the data being created.
                                Ex: campaign, list, etc
        data                :   dict
                                Data dictionary of the data which is being created
        filter              :   str
                                The filter string which can be used to filter the data
                                Ex: `listname eq 'demo_list'` is searching for a marketing list with name 'demo_list'


        Example Input:
        -------------
        data_type         =   "campaign"
        data                =   {
                                    "name": "Demo campaign 1",
                                    ...
                                    // Other fields. Please refer the link below
                                    https://docs.microsoft.com/en-us/dynamics365/customer-engagement/web-api/campaign?view=dynamics-ce-odata-9
                                    ...
                                }
        filter              =   "name eq 'Demo campaign 1'"
        """

        try:
            obj_data = self.get_data(data_type, filter=filter, **kwargs).get("value")[0]
            return obj_data, False
        except IndexError:
            logging.info("Required data not found. Creating new data for {data_type}".format(**locals()))
            obj_data = self.create_data(data_type, data, **kwargs)
            return obj_data, True

    # contact section, see the documentation https://docs.microsoft.com/es-es/dynamics365/customer-engagement/web-api/contact?view=dynamics-ce-odata-9
    def get_contacts(self, **kwargs):
        return self._get("contacts", **kwargs)

    def create_contact(self, **kwargs):
        if kwargs is not None:
            params = {}
            params.update(kwargs)
            return self._post("contacts", json=params)

    def delete_contact(self, id):
        if id != "":
            return self._delete("contacts({0})".format(id))
        raise Exception("To delete a contact is necessary the ID")

    def update_contact(self, id, **kwargs):
        if id != "":
            url = "contacts({0})".format(id)
            params = {}
            if kwargs is not None:
                params.update(kwargs)
            return self._patch(url, json=params)
        raise Exception("To update a contact is necessary the ID")

    # account section, see the documentation https://docs.microsoft.com/es-es/dynamics365/customer-engagement/web-api/account?view=dynamics-ce-odata-9
    def get_accounts(self, **kwargs):
        return self._get("accounts", **kwargs)

    def create_account(self, **kwargs):
        if kwargs is not None:
            params = {}
            params.update(kwargs)
            return self._post("accounts", json=params)

    def delete_account(self, id):
        if id != "":
            return self._delete("accounts({0})".format(id))
        raise Exception("To delete an account is necessary the ID")

    def update_account(self, id, **kwargs):
        if id != "":
            url = "accounts({0})".format(id)
            params = {}
            if kwargs is not None:
                params.update(kwargs)
            return self._patch(url, json=params)
        raise Exception("To update an account is necessary the ID")

    # opportunity section, see the documentation https://docs.microsoft.com/es-es/dynamics365/customer-engagement/web-api/opportunity?view=dynamics-ce-odata-9
    def get_opportunities(self, **kwargs):
        return self._get("opportunities", **kwargs)

    def create_opportunity(self, **kwargs):
        if kwargs is not None:
            params = {}
            params.update(kwargs)
            return self._post("opportunities", json=params)

    def delete_opportunity(self, id):
        if id != "":
            return self._delete("opportunities({0})".format(id))
        raise Exception("To delete an account is necessary the ID")

    def update_opportunity(self, id, **kwargs):
        if id != "":
            url = "opportunities({0})".format(id)
            params = {}
            if kwargs is not None:
                params.update(kwargs)
            return self._patch(url, json=params)
        raise Exception("To update an opportunity is necessary the ID")

    # leads section, see the documentation https://docs.microsoft.com/es-es/dynamics365/customer-engagement/web-api/lead?view=dynamics-ce-odata-9
    def get_leads(self, **kwargs):
        return self._get("leads", **kwargs)

    def create_lead(self, **kwargs):
        if kwargs is not None:
            params = {}
            params.update(kwargs)
            return self._post("leads", json=params)

    def update_lead(self, id, **kwargs):
        if id != "":
            url = "leads({0})".format(id)
            params = {}
            if kwargs is not None:
                params.update(kwargs)
            return self._patch(url, json=params)
        raise NotFoundError("Missing param `id` when updating a lead")

    def delete_lead(self, id):
        if id != "":
            return self._delete("leads({0})".format(id))
        raise NotFoundError("Missing param `id` when deleting a lead")

    # campaign section, see the documentation https://docs.microsoft.com/es-es/dynamics365/customer-engagement/web-api/campaign?view=dynamics-ce-odata-9
    def get_campaigns(self, **kwargs):
        return self._get("campaigns", **kwargs)

    def create_campaign(self, campaign, **kwargs):
        if campaign:
            return self._post("campaigns", json=campaign, **kwargs)
        raise NotFoundError("Missing param `campaign`(dict) when creating a campaign")

    def update_campaign(self, id, campaign, **kwargs):
        if id != "" and campaign is not None:
            url = "campaigns({id})".format(**locals())
            return self._patch(url, json=campaign, **kwargs)
        raise NotFoundError(
            "Missing params `id` or `campaign`(dict) when creating a campaign"
        )

    def retrieve_data(self, object_type, object_id, **kwargs):
        if object_id is not None and object_type is not None:
            url = "{object_type}({object_id})".format(**locals())
            return self._get(url, **kwargs)
        raise NotFoundError("Missing param `object_type` or `object_id` when retrieving data")

    def retrieve_campaign(self, id, **kwargs):
        if id != "":
            url = "campaigns({id})".format(**locals())
            return self._get(url, **kwargs)
        raise NotFoundError("Missing param `id` when retrieving a campaign")

    def delete_campaign(self, id):
        if id != "":
            return self._delete("campaigns({0})".format(id))
        raise NotFoundError("Missing param `id` when deleting a campaign")

    # lists section, see the documentation https://docs.microsoft.com/es-es/dynamics365/customer-engagement/web-api/list?view=dynamics-ce-odata-9
    def get_lists(self, **kwargs):
        return self._get("lists", **kwargs)

    def create_list(self, list_data, **kwargs):
        if list_data:
            return self._post("lists", json=list_data, **kwargs)
        raise NotFoundError("Missing param `list_data`(dict) when creating a list")

    def update_list(self, id, list_data={}, **kwargs):
        if id != "":
            url = "lists({0})".format(id)
            return self._patch(url, json=list_data, **kwargs)
        raise NotFoundError("Missing param `id` when updating a list")

    def delete_list(self, id):
        if id != "":
            return self._delete("lists({0})".format(id))
        raise NotFoundError("Missing param `id` when deleting a list")

    def add_list_members_list(self, json, **kwargs):
        if json:
            return self._post("AddListMembersList", json=json, **kwargs)
        raise NotFoundError(
            "Missing param `json` when adding a list of members to a marketing list"
        )

    def add_campaign_to_list(self, id, campaign_id, **kwargs):
        if id and campaign_id:
            json_data = {
                "Campaign": {
                    "campaignid": campaign_id,
                    "@odata.type": "Microsoft.Dynamics.CRM.campaign",
                }
            }
            return self._post(
                "lists({id})/Microsoft.Dynamics.CRM.AddItemCampaign".format(**locals()),
                json=json_data,
                **kwargs
            )
        raise NotFoundError(
            "Missing params `id` or `campaignid` when adding a campaign to a marketing list"
        )

    # upsert section
    def upsert_data(self, key_data, member_type, json={}, **kwargs):
        if key_data and member_type:
            url = "{member_type}({key_data})".format(**locals())
            return self._patch(url, json=json, **kwargs)
        raise NotFoundError(
            "Missing params `member_type` or `key_data` when upserting the data"
        )

    # batch section
    def batch_data(self, payload, **kwargs):
        if payload:
            return self._post("$batch", data=payload, **kwargs)
        return NotFoundError("Missing params `payload` when calling this API")
