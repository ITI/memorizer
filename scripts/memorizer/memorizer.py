import sys,threading,os,subprocess,operator
from collections import defaultdict

mem_path = "/sys/kernel/debug/memorizer/"
trace_path = "/sys/kernel/debug/tracing/"
completed = False

def worker(cmd):
  ret = os.system(cmd)    
  if(ret != 0):
    print "Failed attempt on: " + cmd
    cleanup()
    exit(1)

def memManager():
  while(not completed):
    stats = subprocess.check_output(["free"])
    stats_list = stats.split()
    total_mem = float(stats_list[7])
    used_mem = float(stats_list[8])
    memory_usage = used_mem / total_mem
    if(memory_usage > 0.8):
      ret = os.system("sudo cat " + mem_path + "kmap >> test.kmap")
      if ret != 0:
        print "Failed to append kmap to temp file"
        exit(1)
      ret = os.system("sudo echo 1 > " + mem_path + "clear_printed_list")
      if ret != 0:
        print "Failed to clear printed list"
        exit(1)

def postProcessing():
  with open('trace.output','rU') as f:
    i = 0
    counts = defaultdict(int)
    for line in f:
      i+=1
      if i < 12:
        continue
      split_line = line.split()
      length = len(split_line)
      if length != 6 and length != 7:
        print "Bad line format: line#" + str(i) 
        continue
      callee = split_line[-2]
      caller = split_line[-1][2:]
      counts[(caller,callee)] += 1
    with open('counts.txt', 'w') as out:
      sorted_by_vals = sorted(counts.items(), key=operator.itemgetter(1),reverse=True)
      out.write("Caller"+"\t"+"Callee"+"\t"+"Count"+"\t\n\n")
      for ((caller,callee),count) in sorted_by_vals:
        out.write(caller+"\t"+callee+"\t"+str(count)+"\n")
            
def startup():
  # Memorizer Startup
  ret = os.system("sudo echo 1 > " + mem_path + "clear_object_list")
  if ret != 0:
    print "Failed to clear object list"
    exit(1)
  ret = os.system("sudo echo 0 > " + mem_path + "print_live_obj")
  if ret != 0:
    print "Failed to disable live object dumping"
    exit(1)
  ret = os.system("sudo echo 1 > " + mem_path + "memorizer_enabled")
  if ret != 0:
    print "Failed to enable memorizer object allocation tracking"
    exit(1)
  # Temporarily disabling -- enable later on
  ret = os.system("sudo echo 0 > " + mem_path + "memorizer_log_access")
  if ret != 0:
    print "Failed to enable memorizer object access tracking"
    exit(1)
  # ftrace startup
  ret = os.system("sudo echo function > " + trace_path + "current_tracer")
  if ret != 0:
    print "Failed to add function to list of tracers"
    exit(1)
  # Clear trace buffer
  ret = os.system("sudo echo > " + trace_path + "trace")
  if ret != 0:
    print "Failed to clear the trace buffer"
    exit(1)
  ret = os.system("sudo echo 1 > " + trace_path + "tracing_on")
  if ret != 0:
    print "Failed to enable function tracing"
    exit(1)

def cleanup():
  # ftrace cleanup 
  ret = os.system("sudo echo 0 > " + trace_path + "tracing_on")
  if ret != 0 :
    print "Failed to disable function tracing"
    exit(1)
  # Memorizer cleanup
  ret = os.system("sudo echo 0 > " + mem_path + "memorizer_enabled")
  if ret != 0:
    print "Failed to disable memorizer object allocation tracking"
    exit(1)
  ret = os.system("sudo echo 0 > " + mem_path + "memorizer_log_access")
  if ret != 0:
    print "Failed to disable memorizer object access tracking"
    exit(1)
  # Print stats
  ret = os.system("sudo cat " + mem_path + "show_stats")
  if ret != 0:
    print "Failed to display memorizer stats"
    exit(1)
  ret = os.system("sudo cat " + trace_path + "per_cpu/cpu0/stats")
  if ret != 0:
    print "Failed to display ftrace stats"
    exit(1)
  ret = os.system("sudo echo 1 > " + mem_path + "print_live_obj")
  if ret != 0:
    print "Failed to enable live object dumping"
    exit(1)
  # Make local copies of outputs
  ret = os.system("sudo cat " + mem_path + "kmap >> test.kmap")
  if ret != 0:
    print "Failed to copy live and freed objs to kmap"
    exit(1)
  ret = os.system("sudo echo 1 > " + mem_path + "clear_object_list")
  if ret != 0:
    print "Failed to clear all freed objects in obj list"
    exit(1)
  ret = os.system("sudo cp " + trace_path + "trace trace.output") 
  if ret != 0:
    print "Failed to copy the trace output file"
    exit(1)

def main(argv):
  global completed
  startup()
  print "Startup completed. Generating threads."
  manager = threading.Thread(target=memManager, args=())
  manager.start()
  threads = []
  for i in xrange(1, len(argv)):
    try:
      t = threading.Thread(target=worker, args=(argv[i],))
      threads.append(t)
      t.start()
    except:
      print "Error: unable to start thread"
  for thr in threads:
    thr.join()
  completed = True
  manager.join()
  print "Threads ran to completion. Cleaning up."
  cleanup()
  print "Cleanup successful. Performing post processing."
  postProcessing()
  print "Post processing complete. Exiting."
  return 0

if __name__ == "__main__":
  main(sys.argv)
