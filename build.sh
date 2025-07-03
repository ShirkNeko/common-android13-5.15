export PATH=/root/kernel/tool/google_clang21/bin:$PATH
export CROSS_COMPILE=aarch64-linux-gnu-
export CROSS_COMPILE_COMPAT=arm-linux-gnueabi-

git submodule init
git submodule update

curl -LSs "https://raw.githubusercontent.com/SukiSU-Ultra/SukiSU-Ultra/main/kernel/setup.sh" | bash -s susfs-main

rm -rf out

make LLVM=1 LLVM_IAS=1 ARCH=arm64 CC="ccache clang" HOSTCC="ccache clang" HOSTCXX="ccache clang++" O=out gki_defconfig

scripts/config --file out/.config \
      -e LTO_CLANG \
      -d LTO_NONE \
      -e LTO_CLANG_THIN \
      -d LTO_CLANG_FULL \
      -e THINLTO \
      -d ARM64_BTI_KERNEL 
      
make LLVM=1 LLVM_IAS=1 ARCH=arm64 CC="ccache clang" HOSTCC="ccache clang" HOSTCXX="ccache clang++" O=out -j12 2>&1 | tee build.log


cd out/arch/arm64/boot

curl -LSs "https://raw.githubusercontent.com/ShirkNeko/SukiSU_patch/refs/heads/main/kpm/patch_linux" -o patch
chmod 777 patch
./patch
rm -rf Image
mv oImage Image
mv Image ../../../../AnyKernel3
cd ../../../../AnyKernel3
zip -r AnyKernel3-android13-5.15.zip
mv AnyKernel3-android13-5.15.zip ..