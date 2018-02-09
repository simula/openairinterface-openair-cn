#!/usr/bin/env python

"""
Copyright (c) 2016-present, Facebook, Inc.
All rights reserved.

This source code is licensed under the BSD-style license found in the
LICENSE file in the root directory of this source tree. An additional grant
of patent rights can be found in the PATENTS file in the same directory.
"""

from mme_app_driver import MMEAppDriver


def test_non_blocking_mme_init():
    """Test that MME startup does not block during init phase.

    Tests very specifically for s6a init running without blocking MME startup.
    """
    log_conditions = (  # In regex form
        r'Initializing S6a interface',  # S6A init is running
        r'S6a peer connection attempt \d+ / \d+',  # S6A attempting to connect
        r'MME app initialization complete',  # MME proceeded past init steps
    )
    MMEAppDriver().run(log_conditions=log_conditions)


def main():
    """Main method for testing."""
    test_non_blocking_mme_init()

if __name__ == '__main__':
    main()
