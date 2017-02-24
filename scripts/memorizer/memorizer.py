import sys
import threading
import os
import subprocess

mem_path = "/sys/kernel/debug/memorizer/"
completed = False

def worker(cmd):
    ret = os.system(cmd)    
    if(ret != 0):
        print "Failed attempt on: " + cmd

def memManager():
    while(not completed):
        stats = subprocess.check_output(["free"])
        stats_list = stats.split()
        total_mem = float(stats_list[7])
        used_mem = float(stats_list[8])
        memory_usage = used_mem / total_mem
        if(memory_usage > 0.8):
            os.system("sudo cat " + mem_path + "kmap >> test.kmap")
            os.system("sudo echo 1 > " + mem_path + "clear_printed_list")
            
def main():
    global completed
    print "Clearing obj list"
    os.system("sudo echo 1 > " + mem_path + "clear_object_list")
    print "Disabling live object dumping"
    os.system("sudo echo 0 > " + mem_path + "print_live_obj")
    print "Enabling memorizer object allocation tracking"
    os.system("sudo echo 1 > " + mem_path + "memorizer_enabled")
    print "Enabling memorizer object access tracking"
    os.system("sudo echo 1 > " + mem_path + "memorizer_log_access")
    manager = threading.Thread(target=memManager, args=())
    manager.start()
    threads = []
    for i in xrange(1, len(sys.argv)):
        try:
            t = threading.Thread(target=worker, args=(sys.argv[i],))
            threads.append(t)
            t.start()
        except:
            print "Error: unable to start thread"
    for thr in threads:
        thr.join()
    print "All threads completed, stopping memory manager"
    completed = True
    manager.join()
    print "Disabling memorizer object allocation tracking"
    os.system("sudo echo 0 > " + mem_path + "memorizer_enabled")
    print "Disabling memorizer object access tracking"
    os.system("sudo echo 0 > " + mem_path + "memorizer_log_access")
    os.system("sudo cat " + mem_path + "show_stats")
    print "Copying live and freed objs to kmap"
    os.system("sudo echo 1 > " + mem_path + "print_live_obj")
    os.system("sudo cat " + mem_path + "kmap >> test.kmap")
    print "Clearing all freed objects in obj list"
    os.system("sudo echo 1 > " + mem_path + "clear_object_list")

if __name__ == "__main__":
    main()
