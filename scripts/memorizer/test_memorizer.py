import unittest,memorizer,subprocess,sys

mem_path = "/sys/kernel/debug/memorizer/"
trace_path = "/sys/kernel/debug/tracing/"

class TestMemorizer(unittest.TestCase):
  def setUp(self):
    pass

  def startup(self):
    memorizer.startup()
    ret = subprocess.check_output(["sudo","cat",mem_path+"memorizer_enabled"]) 
    self.assertEqual(ret,"Y\n")
    ret = subprocess.check_output(["sudo","cat",mem_path+"memorizer_log_access"])
    #Change to Y when resolve softlock
    self.assertEqual(ret,"N\n")
    ret = subprocess.check_output(["sudo","cat",mem_path+"print_live_obj"])
    self.assertEqual(ret,'N\n')
    ret = subprocess.check_output(["sudo","cat",trace_path+"current_tracer"])
    self.assertEqual(ret,"function\n")
    ret = subprocess.check_output(["sudo","cat",trace_path+"tracing_on"])
    self.assertEqual(ret,"1\n")

  def cleanup(self):
    memorizer.cleanup()
    ret = subprocess.check_output(["sudo","cat",mem_path+"memorizer_enabled"]) 
    self.assertEqual(ret,"N\n")
    ret = subprocess.check_output(["sudo","cat",mem_path+"memorizer_log_access"])
    self.assertEqual(ret,"N\n")
    ret = subprocess.check_output(["sudo","cat",mem_path+"print_live_obj"])
    self.assertEqual(ret,"Y\n")
    ret = subprocess.check_output(["sudo","cat",trace_path+"tracing_on"])
    self.assertEqual(ret,"0\n")
  def test_kernel_fns(self):
    self.startup()
    self.cleanup()

  def test_main(self):
    args = [sys.argv[0],"ls"]
    ret = memorizer.main(args)
    self.assertEqual(ret,0)

  def tearDown(self):
    pass

    
def main():
  unittest.main()

if __name__ == '__main__':
  main()
