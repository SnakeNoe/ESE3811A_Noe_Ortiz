################################################################################
# Automatically-generated file. Do not edit!
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
../mmcau/fsl_mmcau.c 

C_DEPS += \
./mmcau/fsl_mmcau.d 

OBJS += \
./mmcau/fsl_mmcau.o 


# Each subdirectory must supply rules for building sources it contributes
mmcau/%.o: ../mmcau/%.c mmcau/subdir.mk
	@echo 'Building file: $<'
	@echo 'Invoking: MCU C Compiler'
	arm-none-eabi-gcc -std=gnu99 -D__REDLIB__ -DCPU_MK64FN1M0VLL12 -DCPU_MK64FN1M0VLL12_cm4 -DPRINTF_ADVANCED_ENABLE=1 -DPRINTF_FLOAT_ENABLE=1 -DFREESCALE_KSDK_BM -DMBEDTLS_CONFIG_FILE='"ksdk_mbedtls_config.h"' -DFRDM_K64F -DFREEDOM -DSERIAL_PORT_TYPE_UART=1 -DMCUXPRESSO_SDK -DSDK_DEBUGCONSOLE=1 -D__MCUXPRESSO -D__USE_CMSIS -DDEBUG -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\source" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\drivers" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\mmcau" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\mbedtls\include" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\mbedtls\library" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\mbedtls\port\ksdk" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\utilities" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\device" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\component\uart" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\component\serial_manager" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\component\lists" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\CMSIS" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\board" -I"C:\Users\noe_9\Documents\MCUXpressoIDE_11.8.0_1165\workspace\frdmk64f_mbedtls_benchmark\frdmk64f\mbedtls_examples\mbedtls_benchmark" -O0 -fno-common -g3 -fomit-frame-pointer -c -ffunction-sections -fdata-sections -ffreestanding -fno-builtin -fmerge-constants -fmacro-prefix-map="$(<D)/"= -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -D__REDLIB__ -fstack-usage -specs=redlib.specs -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.o)" -MT"$(@:%.o=%.d)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '


clean: clean-mmcau

clean-mmcau:
	-$(RM) ./mmcau/fsl_mmcau.d ./mmcau/fsl_mmcau.o

.PHONY: clean-mmcau

