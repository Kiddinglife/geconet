################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/AuthenticatedEncryption.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/EasyHandshake.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/KeyAgreement.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/KeyAgreementInitiator.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/KeyAgreementResponder.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/Keys.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/TunnelTLS.cpp 

OBJS += \
./thirdparty/cat/src/crypt/tunnel/AuthenticatedEncryption.o \
./thirdparty/cat/src/crypt/tunnel/EasyHandshake.o \
./thirdparty/cat/src/crypt/tunnel/KeyAgreement.o \
./thirdparty/cat/src/crypt/tunnel/KeyAgreementInitiator.o \
./thirdparty/cat/src/crypt/tunnel/KeyAgreementResponder.o \
./thirdparty/cat/src/crypt/tunnel/Keys.o \
./thirdparty/cat/src/crypt/tunnel/TunnelTLS.o 

CPP_DEPS += \
./thirdparty/cat/src/crypt/tunnel/AuthenticatedEncryption.d \
./thirdparty/cat/src/crypt/tunnel/EasyHandshake.d \
./thirdparty/cat/src/crypt/tunnel/KeyAgreement.d \
./thirdparty/cat/src/crypt/tunnel/KeyAgreementInitiator.d \
./thirdparty/cat/src/crypt/tunnel/KeyAgreementResponder.d \
./thirdparty/cat/src/crypt/tunnel/Keys.d \
./thirdparty/cat/src/crypt/tunnel/TunnelTLS.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/crypt/tunnel/AuthenticatedEncryption.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/AuthenticatedEncryption.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/tunnel/EasyHandshake.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/EasyHandshake.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/tunnel/KeyAgreement.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/KeyAgreement.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/tunnel/KeyAgreementInitiator.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/KeyAgreementInitiator.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/tunnel/KeyAgreementResponder.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/KeyAgreementResponder.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/tunnel/Keys.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/Keys.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/crypt/tunnel/TunnelTLS.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/crypt/tunnel/TunnelTLS.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


