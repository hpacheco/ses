import subprocess
from time import sleep
import sys



iter = 0
max = 1000
seed = 12345
win = False
while (not win and iter < max):
  print ("%d/%d" % (iter,max))
  #get fuzz input
  fuzzer = subprocess.Popen(["blab", "-s",str(seed),"-e","(\"w\"|\"s\"|\"a\"|\"d\")*"],stdout=subprocess.PIPE)
  inp, err = fuzzer.communicate()
  print ("trying %s" % inp)
  fuzzee = subprocess.Popen([sys.argv[1],inp],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
  out, err = fuzzee.communicate()
  print ("trying %s" % out)
  win = out.find(b"You win") >= 0
  seed = seed + 1
  iter = iter + 1

if (win): print ("win with %s" % inp)
else: print ("loose")
