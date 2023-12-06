import base64
from typing import Dict

from django import template

register = template.Library()


@register.simple_tag(takes_context=True)
def auth_magic_link(context: Dict) -> str:
    """
    :return: context("base_url") + base64.urlsafe_b64encode(context["username")/context("token"))
    """
    token = base64.urlsafe_b64encode(
        bytes(f"{context['username']}/{context['token']}", "utf-8")
    ).decode("utf-8")
    url = f"{context['base_url']}{token}"
    if context.get("redirect_path"):
        url += f"?redirect_path={context['redirect_path']}"
    return url
