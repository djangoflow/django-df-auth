from django.db import models

import re


class PhoneNumberRule(models.Model):
    class Type(models.TextChoices):
        allow = "allow"
        disallow = "disallow"

    type = models.CharField(max_length=10, choices=Type.choices, default=Type.disallow)
    number_regex = models.CharField(max_length=255)

    @classmethod
    def check_number(cls, number: str) -> bool:
        """
        Allow if there is at least one math 'allow' rule
        Disallow if all matched rules are 'disallow'
        Allow by default if no rules matched
        """
        allow = True
        for rule in cls.objects.all():
            if re.match(rule.number_regex, number):
                allow = rule.type == cls.Type.allow
                if allow:
                    break
        return allow
