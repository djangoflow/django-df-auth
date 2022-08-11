from django import template

import base64


register = template.Library()


@register.simple_tag(takes_context=True)
def auth_magic_link(context):
    """
    :return: context("base_url") + base64.urlsafe_b64encode(context["username")/context("token"))
    """
    token = base64.urlsafe_b64encode(
        bytes(f"{context['username']}/{context['token']}", "utf-8")
    ).decode("utf-8")
    return f"{context['base_url']}{token}"
