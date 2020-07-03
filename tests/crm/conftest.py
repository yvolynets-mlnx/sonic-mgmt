import pytest
import time
import logging

from test_crm import RESTORE_CMDS

logger = logging.getLogger(__name__)

def pytest_runtest_teardown(item, nextitem):
    """ called after ``pytest_runtest_call``.

    :arg nextitem: the scheduled-to-be-next test item (None if no further
                   test item is scheduled).  This argument can be used to
                   perform exact teardowns, i.e. calling just enough finalizers
                   so that nextitem only needs to call setup-functions.
    """
    test_crm_cli_res = RESTORE_CMDS["crm_cli_res"]
    restore_cmd = "bash -c \"crm config thresholds {crm_cli_res} type percentage && crm config thresholds {crm_cli_res} low 70 && crm config thresholds {crm_cli_res} high 85\""
    if not item.rep_call.skipped:
        # Restore CRM threshods
        if test_crm_cli_res:
            logger.info("Restore CRM thresholds. Execute - {}".format(restore_cmd.format(crm_cli_res=test_crm_cli_res)))
            item.funcargs["duthost"].command(restore_cmd.format(crm_cli_res=test_crm_cli_res))

        # if item.rep_call.failed:
        test_name = item.function.func_name
        logger.info("Execute test cleanup")
        # Restore DUT after specific test steps
        # Test case name is used to mitigate incorrect cleanup if some of tests was failed on cleanup step and list of
        # cleanup commands was not cleared
        for cmd in RESTORE_CMDS[test_name]:
            logger.info(cmd)
            item.funcargs["duthost"].shell(cmd + " 2> /dev/null || true")
            time.sleep(2)
        RESTORE_CMDS[test_name] = []
