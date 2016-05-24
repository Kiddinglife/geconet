################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/rand/MersenneTwister.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/rand/StdRand.cpp 

OBJS += \
./thirdparty/cat/src/rand/MersenneTwister.o \
./thirdparty/cat/src/rand/StdRand.o 

CPP_DEPS += \
./thirdparty/cat/src/rand/MersenneTwister.d \
./thirdparty/cat/src/rand/StdRand.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/rand/MersenneTwister.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/rand/MersenneTwister.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/rand/StdRand.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/rand/StdRand.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


