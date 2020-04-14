import pytest

from test_crm import ADD_RM_CMDS


def pytest_runtest_teardown(item, nextitem):
    """ called after ``pytest_runtest_call``.

    :arg nextitem: the scheduled-to-be-next test item (None if no further
                   test item is scheduled).  This argument can be used to
                   perform exact teardowns, i.e. calling just enough finalizers
                   so that nextitem only needs to call setup-functions.
    """
    test_crm_cli_res = item.obj.func_defaults[0]
    restore_cmd = "bash -c \"crm config thresholds {crm_cli_res} type percentage && crm config thresholds {crm_cli_res} low 70 && crm config thresholds {crm_cli_res} high 85\""
    # Restore CRM threshods
    item.funcargs["duthost"].command(restore_cmd.format(crm_cli_res=test_crm_cli_res))

    if item.rep_call.failed:
        # Restore DUT after specific test steps
        item.funcargs["duthost"].shell(ADD_RM_CMDS[item.name]["rm"] + " 2> /dev/null || true")

