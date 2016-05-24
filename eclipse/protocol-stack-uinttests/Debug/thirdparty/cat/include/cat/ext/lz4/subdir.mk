################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
/home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/include/cat/ext/lz4/lz4.c 

OBJS += \
./thirdparty/cat/include/cat/ext/lz4/lz4.o 

C_DEPS += \
./thirdparty/cat/include/cat/ext/lz4/lz4.d 


# Each subdirectory must supply rules for building sources it contributes
thirdparty/cat/include/cat/ext/lz4/lz4.o: /home/jakez/2016209/geco-sctp-cplus/thirdparty/cat/include/cat/ext/lz4/lz4.c
	@echo 'Building file: $<'
	@echo 'Invoking: Cross GCC Compiler'
	gcc -std=c11 -O0 -g3 -Wall -c -fmessage-length=0 -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


