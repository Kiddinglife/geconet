################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/HMAC_MD5.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/Skein.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/Skein256.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/Skein512.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/VHash.cpp 

OBJS += \
./thirdparty/cat/src/crypt/hash/HMAC_MD5.o \
./thirdparty/cat/src/crypt/hash/Skein.o \
./thirdparty/cat/src/crypt/hash/Skein256.o \
./thirdparty/cat/src/crypt/hash/Skein512.o \
./thirdparty/cat/src/crypt/hash/VHash.o 

CPP_DEPS += \
./thirdparty/cat/src/crypt/hash/HMAC_MD5.d \
./thirdparty/cat/src/crypt/hash/Skein.d \
./thirdparty/cat/src/crypt/hash/Skein256.d \
./thirdparty/cat/src/crypt/hash/Skein512.d \
./thirdparty/cat/src/crypt/hash/VHash.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/crypt/hash/HMAC_MD5.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/HMAC_MD5.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/hash/Skein.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/Skein.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/hash/Skein256.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/Skein256.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/hash/Skein512.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/Skein512.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/hash/VHash.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/hash/VHash.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


