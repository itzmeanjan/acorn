CXX = dpcpp
CXXFLAGS = -std=c++20 -Wall -Weverything -Wno-c++98-compat -Wno-c++98-c++11-compat-binary-literal -Wno-c++98-compat-pedantic
OPTFLAGS = -O3
IFLAGS = -I ./include

# Actually compiled code to be executed on host CPU, to be used only for testing functional correctness
FPGA_EMU_FLAGS = -DFPGA_EMU -fintelfpga

# Another option is using `intel_s10sx_pac:pac_s10` as FPGA board and if you do so ensure that
# on Intel Devcloud you use `fpga_runtime:stratix10` as offload target
#
# Otherwise if you stick to Arria 10 board, consider offloading to `fpga_runtime:arria10` attached VMs
# on Intel Devcloud ( default target board used in this project )
FPGA_OPT_FLAGS = -DFPGA_HW -fintelfpga -fsycl-link=early -Xshardware -Xsboard=intel_a10gx_pac:pac_a10

# Consider enabing -Xsprofile, when generating h/w image, so that execution can be profiled
# using Intel Vtune
#
# Consider reading 👆 note ( on top of `FPGA_OPT_FLAGS` definition ) for changing target board
FPGA_HW_FLAGS = -DFPGA_HW -fintelfpga -Xshardware -Xsboard=intel_a10gx_pac:pac_a10

all: test_acorn

test/a.out: test/acorn.cpp include/*.hpp
	$(CXX) $(CXXFLAGS) $(OPTFLAGS) $(IFLAGS) $< -o $@

test_acorn: test/a.out
	./test/a.out

clean:
	find . -name '*.out' -o -name '*.o' -o -name 'fpga_opt_test.*' | xargs rm -rf

format:
	find . -name '*.cpp' -o -name '*.hpp' | xargs clang-format -i --style=Mozilla

bench/a.out: bench/acorn.cpp include/*.hpp
	# make sure you've google-benchmark globally installed
	# see https://github.com/google/benchmark/tree/60b16f1#installation
	$(CXX) $(CXXFLAGS) -Wno-global-constructors $(OPTFLAGS) $(IFLAGS) $< -lbenchmark -lpthread -o $@

benchmark: bench/a.out
	./$<

fpga_emu_test: test/fpga_emu_test.out
	./$<

test/fpga_emu_test.out: test/acorn_fpga.cpp include/*.hpp
	$(CXX) $(CXXFLAGS) $(FPGA_EMU_FLAGS) $(OPTFLAGS) $(IFLAGS) $< -o $@

fpga_opt_test: test/acorn_fpga.cpp include/*.hpp
	# output not supposed to be executed, instead consume report generated
	# inside `test/fpga_opt_test.prj/reports/` diretory
	$(CXX) $(CXXFLAGS) $(FPGA_OPT_FLAGS) $(OPTFLAGS) $(IFLAGS) $< -o test/$@.a

fpga_hw_test: test/acorn_fpga.cpp include/*.hpp
	$(CXX) $(CXXFLAGS) $(FPGA_HW_FLAGS) $(OPTFLAGS) $(IFLAGS) -reuse-exe=test/$@.out $< -o test/$@.out

fpga_emu_bench: bench/fpga_emu_bench.out
	./$<

bench/fpga_emu_bench.out: bench/acorn_fpga.cpp include/*.hpp
	$(CXX) $(CXXFLAGS) -Wno-padded $(FPGA_EMU_FLAGS) $(OPTFLAGS) $(IFLAGS) $< -o $@

fpga_hw_bench: bench/acorn_fpga.cpp include/*.hpp
	$(CXX) $(CXXFLAGS) -Wno-padded $(FPGA_HW_FLAGS) $(OPTFLAGS) $(IFLAGS) -reuse-exe=bench/$@.out $< -o bench/$@.out
