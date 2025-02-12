import ida_auto
import ida_pro

# wait for the pre-analysis of IDA to be terminated
ida_auto.auto_wait()

# exit IDA with the given return code (otherwise remains opened)
ida_pro.qexit(0)
