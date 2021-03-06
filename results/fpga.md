# Benchmarking Acorn-128 encrypt/ decrypt kernel on Intel Arria 10 FPGA

I've implemented single work-item ( using SYCL `single_task` ) Acorn-128 encrypt/ decrypt FPGA kernels, which can be used for computing encrypted text using Acorn-128 authenticated encryption algorithm/ decrypted text using Acorn-128 verified decryption algorithm on N -many independent & non-overlapping plain/ cipher text byteslices & respective associated data byteslices.

> Note, associated data byteslices are never encrypted, only plain text byteslices are.

N -many invocations of Acorn-128 encrypt/ decrypt routine are not spawn in well familiar multi work-item data-parallel fashion ( read SYCL `parallel_for` ), instead single work-item kernel's iterative execution style is preferred, while leveraging deep pipelining in synthesized FPGA h/w image.

In following benchmark setting associated data length is kept same ( = 32 -bytes ), while plain/ cipher text length is chosen to be power of 2 ( -bytes ), from range [64..4096] ( read both ends are inclusive ). Number of times iteration is executed inside body of single work-item kernel ( i.e. N ) ∈ {2^16, 2^17, 2^18}.

## Job submission

Intel Devcloud is used for submission of FPGA h/w synthesis & h/w image execution jobs.

> Learn more about Intel Devcloud [here](https://www.intel.com/content/www/us/en/developer/tools/devcloud/overview.html).

### Compilation

First prepare job submission script like

```bash
touch build_fpga_bench_hw.sh
```

Put following content inside job submission script

```bash
#!/bin/bash

# file name: build_fpga_bench_hw.sh

# env setup
export PATH=/glob/intel-python/python2/bin/:${PATH}
source /opt/intel/inteloneapi/setvars.sh > /dev/null 2>&1

# hardware compilation
time make fpga_hw_bench
```

Then enqueue job to generate h/w image on `fpga_compile` tagged VM on Intel Devcloud.

```bash
qsub -l nodes=1:fpga_compile:ppn=2 -l walltime=24:00:00 -d . build_fpga_bench_hw.sh
```

Successful submission should generate job id ( looks like `1882236` ), take a note of it.

### Execution

Once FPGA h/w synthesis is finished, another dependent job will kick in to execute synthesized h/w image & collect benchmark metrics.

First prepare job submission script

```bash
touch run_fpga_bench_hw.sh
```

Put following content inside that script

```bash
#!/bin/bash

# file name: run_fpga_bench_hw.sh

# env setup
export PATH=/glob/intel-python/python2/bin/:${PATH}
source /opt/intel/inteloneapi/setvars.sh > /dev/null 2>&1

# hardware image execution
pushd bench; ./fpga_hw_bench.out; popd
```

Now create job dependency graph, using already obtained compilation job id, when submitting execution job.

```bash
qsub -l nodes=1:fpga_runtime:arria10:ppn=2 -d . run_fpga_bench_hw.sh -W depend=afterok:1882236
```

Execution job submission should also generate one job id, though we don't need it at this moment.

> Read more about job submission using `qsub` on Intel Devcloud [here](https://devcloud.intel.com/oneapi/documentation/job-submission)

## Results

### Acorn-128 Authenticated Encryption

```bash
running on pac_a10 : Intel PAC Platform (pac_ee00000)

Benchmarking Acorn-128 encrypt

+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|invocation count|plain text len ( bytes )|associated data len ( bytes )|host-to-device b/w|      kernel b/w|device-to-host b/w|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                      64|                           32|    2.449322 GB/ s|453.980936 MB/ s|    2.630950 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                     128|                           32|    2.873497 GB/ s|757.195382 MB/ s|    3.612867 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                     256|                           32|    3.740407 GB/ s|991.328628 MB/ s|    4.090229 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                     512|                           32|    4.173877 GB/ s|951.123232 MB/ s|    4.281739 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                    1024|                           32|    4.517605 GB/ s|930.523742 MB/ s|    4.467930 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                    2048|                           32|    5.042320 GB/ s|920.078525 MB/ s|    4.910270 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                    4096|                           32|    5.590828 GB/ s|914.842156 MB/ s|    5.622998 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                      64|                           32|    3.278968 GB/ s|454.510230 MB/ s|    3.540591 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                     128|                           32|    3.690099 GB/ s|757.534294 MB/ s|    3.900600 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                     256|                           32|    4.101385 GB/ s|991.846936 MB/ s|    4.199897 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                     512|                           32|    4.437497 GB/ s|951.322692 MB/ s|    4.441039 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                    1024|                           32|    4.942350 GB/ s|930.629909 MB/ s|    4.957086 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                    2048|                           32|    5.616670 GB/ s|920.138471 MB/ s|    5.547224 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                    4096|                           32|    5.882432 GB/ s|914.863884 MB/ s|    5.934086 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                      64|                           32|    4.004750 GB/ s|454.654227 MB/ s|    4.008502 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                     128|                           32|    4.240302 GB/ s|757.771228 MB/ s|    4.239347 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                     256|                           32|    4.420309 GB/ s|992.043467 MB/ s|    4.401233 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                     512|                           32|    5.010631 GB/ s|951.447202 MB/ s|    4.846313 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                    1024|                           32|    5.465086 GB/ s|930.683376 MB/ s|    5.657928 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                    2048|                           32|    5.845599 GB/ s|920.166806 MB/ s|    5.965640 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                    4096|                           32|    6.025828 GB/ s|914.881100 MB/ s|    6.014532 GB/ s|
+----------------+------------------------+-----------------------------+------------------+----------------+------------------+
```

### Acorn-128 Verified Decryption

```bash
running on pac_a10 : Intel PAC Platform (pac_ee00000)

Benchmarking Acorn-128 decrypt

+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|invocation count|cipher text len ( bytes )|associated data len ( bytes )|host-to-device b/w|      kernel b/w|device-to-host b/w|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                       64|                           32|    2.686074 GB/ s|454.236333 MB/ s|    3.301768 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                      128|                           32|    3.159999 GB/ s|757.083596 MB/ s|    3.915775 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                      256|                           32|    3.724251 GB/ s|991.560553 MB/ s|    4.379299 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                      512|                           32|    4.040390 GB/ s|951.127595 MB/ s|    4.581565 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                     1024|                           32|    4.486363 GB/ s|930.524450 MB/ s|    4.647970 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                     2048|                           32|    5.068291 GB/ s|920.087115 MB/ s|    5.070843 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|65536           |                     4096|                           32|    5.653541 GB/ s|914.843168 MB/ s|    5.682070 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                       64|                           32|    3.231462 GB/ s|454.519199 MB/ s|    3.870333 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                      128|                           32|    3.722224 GB/ s|757.509217 MB/ s|    4.318130 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                      256|                           32|    4.106786 GB/ s|991.830977 MB/ s|    4.487968 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                      512|                           32|    4.321944 GB/ s|951.316703 MB/ s|    4.595796 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                     1024|                           32|    4.982195 GB/ s|930.625664 MB/ s|    5.063927 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                     2048|                           32|    5.526422 GB/ s|920.142164 MB/ s|    5.268765 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|131072          |                     4096|                           32|    5.879254 GB/ s|914.868937 MB/ s|    6.129558 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                       64|                           32|    3.869305 GB/ s|454.630939 MB/ s|    4.301018 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                      128|                           32|    4.118306 GB/ s|757.750026 MB/ s|    4.483958 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                      256|                           32|    4.359724 GB/ s|992.039257 MB/ s|    4.855154 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                      512|                           32|    4.971696 GB/ s|951.451595 MB/ s|    5.733523 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                     1024|                           32|    5.462058 GB/ s|930.674212 MB/ s|    5.821104 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                     2048|                           32|    5.837875 GB/ s|920.165961 MB/ s|    6.098168 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
|262144          |                     4096|                           32|    6.008298 GB/ s|914.882625 MB/ s|    6.234264 GB/ s|
+----------------+-------------------------+-----------------------------+------------------+----------------+------------------+
```
