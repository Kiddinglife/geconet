################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
ASM_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/big_x64_elf.asm \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/big_x64_mscoff.asm 

CPP_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BigMontgomery.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BigPseudoMersenne.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BigRTL.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BigTwistedEdwards.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BitMath.cpp \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/MemXOR.cpp 

OBJS += \
./thirdparty/cat/src/math/BigMontgomery.o \
./thirdparty/cat/src/math/BigPseudoMersenne.o \
./thirdparty/cat/src/math/BigRTL.o \
./thirdparty/cat/src/math/BigTwistedEdwards.o \
./thirdparty/cat/src/math/BitMath.o \
./thirdparty/cat/src/math/MemXOR.o \
./thirdparty/cat/src/math/big_x64_elf.o \
./thirdparty/cat/src/math/big_x64_mscoff.o 

CPP_DEPS += \
./thirdparty/cat/src/math/BigMontgomery.d \
./thirdparty/cat/src/math/BigPseudoMersenne.d \
./thirdparty/cat/src/math/BigRTL.d \
./thirdparty/cat/src/math/BigTwistedEdwards.d \
./thirdparty/cat/src/math/BitMath.d \
./thirdparty/cat/src/math/MemXOR.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/src/math/BigMontgomery.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BigMontgomery.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/math/BigPseudoMersenne.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BigPseudoMersenne.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/math/BigRTL.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BigRTL.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/math/BigTwistedEdwards.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BigTwistedEdwards.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/math/BitMath.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/BitMath.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/math/MemXOR.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/MemXOR.cpp
	@echo 'Building file: $<'
	@echo 'Invoking: Cross G++ Compiler'
	g++ -std=c++0x -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googletest/include -I/home/jakez/2016209/geco-sctp-cplus/thirdparty/googlemock/include -I/home/jakez/2016209/geco-sctp-cplus/include -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/math/big_x64_elf.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/big_x64_elf.asm
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Assembler'
	as  -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

thirdparty/cat/src/math/big_x64_mscoff.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/src/math/big_x64_mscoff.asm
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Assembler'
	as  -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


