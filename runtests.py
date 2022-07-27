#!/usr/bin/env python3

import os
import pytest
import sys


def run_tests():
    os.environ["DJANGO_SETTINGS_MODULE"] = "tests.settings"
    pytest.main(sys.argv[1:])


if __name__ == "__main__":
    run_tests()
