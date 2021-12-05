#
# @@-COPYRIGHT-START-@@
#
# Copyright (c) 2014-2016, 2018-2019 Qualcomm Technologies, Inc.
#
# All Rights Reserved.
# Confidential and Proprietary - Qualcomm Technologies, Inc.
#
# 2014-2016 Qualcomm Atheros, Inc.
#
# All Rights Reserved.
# Qualcomm Atheros Confidential and Proprietary.
#
# @@-COPYRIGHT-END-@@
#

from setuptools import setup, find_packages
import os

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.rst')).read()

# Pull the requirements directly from the file
try:
    with open(os.path.join(here, 'requirements.txt'), 'r') as fi:
        reqs = fi.readlines()
except Exception as e:
    print "Failed to parse requirements: " + str(e)
    reqs = []

setup(name='whcdiag',
      version='4.0.0',
      description="Whole Home Coverage - Diagnostic Logging",
      long_description=README,
      classifiers=[
          "Development Status :: 4 - Beta",
      ],
      keywords='whc diag steering',
      author="Qualcomm Atheros, Inc.",
      url="https://www.qualcomm.com/",
      packages=find_packages(exclude=['tests']),
      scripts=['scripts/%s' % f for f in os.listdir('scripts')],
      include_package_data=True,
      zip_safe=True,
      install_requires=reqs,
      setup_requires=["setuptools_git >= 0.3", "flake8 == 2.6.2", "pep8 == 1.5.7"],
      tests_require=['nose', 'coverage', 'mock'],
      entry_points="""
      # -*- Entry points: -*-
      """,
      )
