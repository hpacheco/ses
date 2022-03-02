import subprocess
from time import sleep
import sys

fuzzee = subprocess.Popen([sys.argv[1]],stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=subprocess.PIPE)

enterWis = False
iter = 0
max = 1000
seed = 12458341
crash = fuzzee.returncode != None
while (not crash and iter < max):
  print ("%d/%d" % (iter,max))
  #get fuzz input
  fuzzer = subprocess.Popen(["radamsa", "-s", str(seed), "inputs/2"],stdout=subprocess.PIPE)
  seed = seed + 1
  inp, err = fuzzer.communicate()
  print ("trying %s" % inp)
  out = b""
  while True:
    c = fuzzee.stdout.read(1)
    out = out + c
    if c == b">":
      enterWis = False
      break
    r = out.find(b"Enter some wisdom")
    if r >= 0:
      enterWis = True
      break
    if c==b"": break;

  try:
    fuzzee.stdout.flush()
    fuzzee.stdin.flush()
    if enterWis == False:
      fuzzee.stdin.write(inp+b"\n")
    else:
      fuzzee.stdin.write(inp+b"\n")
    fuzzee.stdin.flush()
  except (BrokenPipeError,IOError): crash=True
  fuzzee.poll()
  crash = crash or fuzzee.returncode != None
  iter = iter + 1

if (not crash):
  print ("did not crash")
else:
  print ("crashed with %s" % inp)
