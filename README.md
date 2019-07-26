# Blink: Fast Connectivity Recovery Entirely in the Data-Plane

This is the repository of [Blink](https://www.usenix.org/conference/nsdi19/presentation/holterbach), which was presented at NSDI'19.

`p4_code` contains the p4_16 implementation of Blink.<br/>
`python_code` contains the Python-based implementation of Blink.<br/>
`controller` contains the controller code of Blink, written in Python.<br/>
`topologies` contains json files to build mininet-based topologies with switches running Blink.<br/>
`vm` contains the configuration files that can be used to build a ready-to-use VM using Vagrant.

# P4 Virtual Machine Installation

To run Blink, we recommend to build a virtual machine following the [instructions](https://github.com/nsg-ethz/Blink/tree/master/vm)
available in the directory `vm`. By the way, these instructions come from the
[p4-learning](https://github.com/nsg-ethz/p4-learning) repositery, which contains all the materials from the [Advanced
Topics in Communication Networks lecture](https://adv-net.ethz.ch) taught at ETH Zurich.

When you use the VM, always use the user `p4`. For instance, after doing `vagrant ssh`, you should write `su p4`. The password is `p4`.

Note that bmv2 should be installed without the log, to make the p4 switches faster (which should be done by default if you do the vagrant installation).

# Building a virtual topology with mininet

Once you have installed the VM, you should find a directory `Blink` in `/home/p4/`. Now, the next step is to build a virtual topology using [mininet](http://mininet.org). To do that, we first need to define the topology in a `json` file. We provide you with the file [5switches.json](https://github.com/nsg-ethz/Blink/blob/master/topologies/5switches.json), which defines the topology below, and that we will use as an example.
To build your own topology, you can find some documentation [here](https://github.com/nsg-ethz/p4-utils#documentation).

```
          +-----+S2+-----+
          |              |
          |              |
H1+----+S1+-----+S3+-----+S5+----+H2
          |              |
          |              |
          +-----+S4+-----+
```

There are other options in the `json` file (such as where to find the p4 program), but you do not need to modify them for our simple example. 


Now, follow these instructions to create a mininet network with the topology above and run `main.p4` in the `p4_code` directory :

1. To create the topology described in `topologies/5switches.json`, you just have to call `p4run`. By default, `p4run`
will look for the file `p4app.json`, so we will configure it to look for the `5switches.json` instead:

   ```bash
   sudo p4run --config topologies/5switches.json
   ```

   This will call a python script that parses the configuration file, creates
   a virtual network of hosts and p4 switches using mininet, compile the p4 program
   and load it in the switches. You can find the p4-utils documentation [here](https://github.com/nsg-ethz/p4-utils).
+
   After running `p4run` you will get the `mininet` CLI prompt.

2. At this point you will have a the topology described above. You can get a terminal in `h1` by either
typing `xterm h1` in the CLI, or by using the `mx` command that comes already installed in the VM:

   ```bash
   mx h1
   ```
   
4. Close all the host-terminals and type `quit` to leave the mininet CLI and clean the network.
   ```bash
   mininet> quit
   ```

   > Alternatives: `exit` or Ctrl-D

# Running Blink

## Configuring the routing

The next step is to run the controller for each p4 switch in the network. The controller will populate the registers so that Blink is ready to fast reroute. For example, the controller will populate the next-hops list, used to indicate which next-hops to use for every destination prefix. You must indicate in a json file the next-hops to use for each switch and for each prefix. We provide you with an example in the file [5switches_routing.json](https://github.com/nsg-ethz/Blink/blob/master/topologies/5switches_routing.json).

Observe that here we differentiate peers, providers and customers. This is an improvement we made and which is not included the in the Blink paper. The effect is that the traffic that can go to customers only and the traffic than can go to customers/peers/providers go through the Blink pipeline independently of each other, like if they were going to two different destination prefixes. If you want to define your own topology and your own policies, you will have to define the per-prefix and per-type-of-traffic next-hops in this file.

## Running the controller

To run the controller, first create the directory `log` where the log files will be stored, and then run the following python script:

```
sudo python -m controller.blink_controller --port 10000 --log_dir log --log_level 20 --routing_file topologies/5switches_routing.json --threshold 31 --topo_db topology.db
```

:exclamation: Observe that here we use a threshold of 15 (instead of 31, i.e., half of the selected flows), because we will only generate 40 flows to test Blink, otherwise the VM will be overloaded which will cause too many retransmissions unrelated to any failure. 

Now, you need to make the connection between the controller and the p4 switches.
To do that, run the following Python script:

```
python -m controller.run_p4_controllers --topo_db topology.db --controller_ip localhost --controller_port 10000 --routing_file topologies/5switches_routing.json
```
Make sure that the port is the same than the one you use with the `blink_controller` script.

> The reason why we used two script is that then the controller code in the `blink_controller` can be used for both the P4 and the Python implementation.

> Note that what `run_p4_controllers` does is essentially just calling the script `p4_controller` for each switch.

The `run_p4_controllers` script regularly dumps in the log files the content of the registers of the p4 switch. You can take a look at the `log` directory. This helps a lot to understand what is going on.

Now you should be able to ping between `h1` and `h2`.
For instance, you can run `ping 10.0.5.2` on `h1`. Or you can use `traceroute` (the p4 switches are programmed to reply to TCP probes only though). For example on `h1`:

```
root@p4:~# traceroute -T  10.0.5.2 -n
traceroute to 10.0.5.2 (10.0.5.2), 30 hops max, 44 byte packets
 1  200.200.200.1  7.747 ms  40.819 ms  40.894 ms
 2  200.200.200.2  40.801 ms  90.819 ms  89.529 ms
 3  200.200.200.5  91.296 ms  93.079 ms  93.667 ms
 4  10.0.5.2  90.057 ms  88.994 ms  91.664 ms
 ```
 
 We programmed the switches reply with source IP address 200.200.200.X with X the switch number.
 
# Testing Blink

Now we will generate some TCP flows between `h1` and `h2` and then we will simulate a failure to see Blink in action.

## Generating traffic

First, go to `h2` with `mx h2` and then in the Blink directory run the receivers:
Make sure to create the directory `log_traffic` before. The log files will be stored in this directory.

```
python -m traffic_generation.run_servers --ports 11000,11040 --log_dir log_traffic```
```

Then, go the `h1` and run 40 flows with an inter packet delay (ipd) of 1s and a duration of 100s:

```
python -m traffic_generation.run_clients --dst_ip 10.0.5.2 --src_ports 11000,11040 --dst_ports 11000,11040 --ipd 1 --duration 100 --log_dir log_traffic/
```

## Simulating a failure

The next step is generate the failure, to do that you can just turn off the interface `s1-eth2` which is fail the link between `s1` and `s2`.

```
sudo ifconfig s1-eth2 down
```

You will see that traffic is quickly rerouted by Blink to s3, which will restore connectivity.
To visualize it, you can `speedometer`. For instance you can run the following three speedometer commands to see the rerouting in real time:

```
speedometer -t s1-eth1
speedometer -t s1-eth2
speedometer -t s1-eth3
```

For instance, this is what you should see:

![alt text](https://github.com/nsg-ethz/Blink/blob/master/speedometer_screenshot.png?raw=true)


Once your are done, you can set the interface `s1-eth2` up:

```
sudo ifconfig s1-eth2 up
```

Then, reset the states of in the p4 switch by writing in the `controller.blink_controller` script the command `reset_states` (you can also simply rerun the `blink_controller` and the `run_p4_controllers` scripts). Now, Blink uses the primary link again and you are ready to run a new experiment!

# Running the Python-based implementation of Blink

The Python code for Blink is available in the directory `python_code`. First, build the python module for the murmur hash functions originally written in C:

```
cd murmur
python setup.py build_ext --inplace
```

After, make the log dir with `mkdir log`.
Then you can start the controller version of the python implementation with:

```
python -m python_code.controller.controller -p 10000 --prefixes_file python_code/pcap/prefixes_file.txt
```

The argument --prefixes_file indicates a file in which there is a list of prefixes that Blink should monitor. We included one pcap file as an example in the directory python_code/pcap. If you just want to consider all the traffic, regardless of their actual destination IP, you can just use 0.0.0.0//0.

Then you need to run the Blink pipeline:

```
python -m python_code.blink.main -p 10000 --pcap python_code/pcap/tx.pcap
```

Feel free to look at the different arguments if you want to tune Blink. The log files that you can use to know when Blink triggered the fast reroute (among other things) are available in the /log directory. For example, the third column in `sliding_window.log` (INFO | 0 is just one column) shows you the sum of all the bins of the sliding window over time. If you run the example above, you should see an increase at around 10s, which is the time of the failure in that trace.
