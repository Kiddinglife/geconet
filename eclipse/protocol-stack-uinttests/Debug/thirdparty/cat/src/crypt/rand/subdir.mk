################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/EntropyGeneric.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/EntropyLinux.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/EntropyWindows.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/EntropyWindowsCE.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/Fortuna.cpp 

OBJS += \
./thirdparty/cat/src/crypt/rand/EntropyGeneric.o \
./thirdparty/cat/src/crypt/rand/EntropyLinux.o \
./thirdparty/cat/src/crypt/rand/EntropyWindows.o \
./thirdparty/cat/src/crypt/rand/EntropyWindowsCE.o \
./thirdparty/cat/src/crypt/rand/Fortuna.o 

CPP_DEPS += \
./thirdparty/cat/src/crypt/rand/EntropyGeneric.d \
./thirdparty/cat/src/crypt/rand/EntropyLinux.d \
./thirdparty/cat/src/crypt/rand/EntropyWindows.d \
./thirdparty/cat/src/crypt/rand/EntropyWindowsCE.d \
./thirdparty/cat/src/crypt/rand/Fortuna.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/crypt/rand/EntropyGeneric.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/EntropyGeneric.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/rand/EntropyLinux.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/EntropyLinux.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/rand/EntropyWindows.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/EntropyWindows.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/rand/EntropyWindowsCE.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/EntropyWindowsCE.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/rand/Fortuna.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/rand/Fortuna.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


