import unittest,memorizer,subprocess,sys,os

mem_path = "/sys/kernel/debug/memorizer/"
trace_path = "/sys/kernel/debug/tracing/"

class TestMemorizer(unittest.TestCase):
  def setUp(self):
    # Give group access to the ltp directory
    ret = os.system("sudo chgrp -R memorizer /opt/")
    if ret != 0:
      print "Failed to change group permissions of /opt/"
      exit(1)
    os.system("sudo chmod -R g+wrx /opt/")
    if ret != 0:
      print "Failed to grant wrx permissions to /opt/"
      exit(1)

  def startup(self):
    memorizer.startup()
    ret = subprocess.check_output(["cat",mem_path+"memorizer_enabled"]) 
    self.assertEqual(ret,"Y\n")
    ret = subprocess.check_output(["cat",mem_path+"memorizer_log_access"])
    #Change to Y when resolve softlock
    self.assertEqual(ret,"N\n")
    ret = subprocess.check_output(["cat",mem_path+"print_live_obj"])
    self.assertEqual(ret,'N\n')
    ret = subprocess.check_output(["cat",trace_path+"current_tracer"])
    self.assertEqual(ret,"function\n")
    ret = subprocess.check_output(["cat",trace_path+"tracing_on"])
    self.assertEqual(ret,"1\n")

  def cleanup(self):
    memorizer.cleanup()
    ret = subprocess.check_output(["cat",mem_path+"memorizer_enabled"]) 
    self.assertEqual(ret,"N\n")
    ret = subprocess.check_output(["cat",mem_path+"memorizer_log_access"])
    self.assertEqual(ret,"N\n")
    ret = subprocess.check_output(["cat",mem_path+"print_live_obj"])
    self.assertEqual(ret,"Y\n")
    ret = subprocess.check_output(["cat",trace_path+"tracing_on"])
    self.assertEqual(ret,"0\n")
    ret = subprocess.check_output(["cat",trace_path+"current_tracer"])
    self.assertEqual(ret,"nop\n")

  def test_kernel_fns(self):
    self.startup()
    self.cleanup()

  def basic_run(self):
    print "Performing basic ls test"
    args = [sys.argv[0],"ls"]
    ret = memorizer.main(args)
    self.assertEqual(ret,0)
    print "Performing wget test"
    args = [sys.argv[0],"wget http://www.sas.upenn.edu/~egme/UPennlogo2.jpg"]
    ret = memorizer.main(args)
    self.assertEqual(ret,0)
    print "Performing tar test"
    args = [sys.argv[0],"tar -czvf image.tar.gz UPennlogo2.jpg"]
    ret = memorizer.main(args)
    self.assertEqual(ret,0)
    print "Basic tests completed. Now cleaning up."
    ret = os.system("rm UPennlogo2.jpg")
    self.assertEqual(ret,0)
    ret = os.system("rm image.tar.gz")
    self.assertEqual(ret,0)
        
  def ltp_run(self):
    print "Performing ltp tests" 
    args = [sys.argv[0],"/opt/ltp/runltp -p -l ltp.log"]
    ret = memorizer.main(args)
    self.assertEqual(ret,0)
    print "See /opt/ltp/results/ltp.log for ltp results"
    

  def test_main(self):
    #User wants to run everything
    if sys.argv[1] == '-h':
      self.basic_run()     
      self.ltp_run()
    #User wants to run ltp
    elif sys.argv[1] == '-m':
      self.ltp_run()
    #User wants to run wget,ls,etc.
    elif sys.argv[1] == '-e':
      self.basic_run()

  def tearDown(self):
    pass
    
def main():
  options = set(['-h','-m','-e'])
  if len(sys.argv) == 1 or not sys.argv[1] in options:
    print "Invalid/missing arg. Please enter -e for basic tests, -m for ltp tests, or -h for a full run of all tests"
    return
  elif len(sys.argv) > 2:
    print "Too many args, please only specify one" 
    return
  runner = unittest.TextTestRunner(verbosity=2)
  itersuite = unittest.TestLoader().loadTestsFromTestCase(TestMemorizer)
  runner.run(itersuite)

if __name__ == '__main__':
  main()
