#!/bin/bash

# Build Arguments
# {build-target-path}

# This script is used to build the coconut firmware distributions that are used by WPC.
# The contents of the distribution includes:
# Path: <product-name>/<product-version>/<build-time>/[files]
#   admin            Config pages
#   html             Contains rinfo.json which provides package information
#   service_manager  Instance of BSD service manager to provide validation
#   shared           Config pages
#   wpc              WPC group pages and BSD config page customizations
#   fw.bin           BSD firmware

# First argument specifies build directory
src=$1
if [ -z "$src" ]
then
	echo "Usage: ./package.sh <build-directory>"
	echo "Output: wpc.tar.gz"
	exit
fi

# Build time from build_info.txt converted to iso format
build_time=`sed -n '1p' ${src}/wpc/build_info.txt`
build_time=`python dateconv.py ${build_time}`
build_time_for_path=`echo ${build_time} | sed s/:/./g`

# Version from build_info.txt
product_version=`sed -n '2p' ${src}/wpc/build_info.txt`

# Product name from build_info.txt
product_name=`sed -n '3p' ${src}/wpc/build_info.txt`

# Revision from hg
revision=`cd $src; git log -n1 --pretty=format:"%H" 2>/dev/null`

# Directory for assembling files
target_base="wpc_tarball"
target="wpc_tarball/${product_name}/${product_version}/${build_time_for_path}"

# Directory containing extension files
ext="extensions"

echo "Product:    $product_name"
echo "Version:    $product_version"
echo "Revision:   $revision"
echo "Timestamp:  $build_time"

# Clean target
rm -rf $target_base
mkdir -p $target

# admin
mkdir $target/admin
cp $src/staging/ui/admin/admin.jgz $target/admin
cp $src/staging/ui/shared.jgz $target/admin
cp $src/staging/ui/ext-all.jgz $target/admin
cp $src/staging/ui/sencha-charts.jgz $target/admin
cp -r $src/staging/ui/resources $target/admin/
cp $ext/config.html $target/admin

# html
# generate the rinfo.json file
mkdir $target/html
rinfo="$target/html/rinfo.json"
echo -e '' > $rinfo
echo "{" >> $rinfo
echo "    \"product_name\": \"$product_name\"," >> $rinfo
echo "    \"product_version\": \"$product_version\"," >> $rinfo
echo "    \"build_time\": \"$build_time\"," >> $rinfo
echo "    \"revision\": \"$revision\"," >> $rinfo
custom=$2
if [ -z "$custom" ]
then
	echo "    \"custom\": null" >> $rinfo
else
	echo "    \"custom\": \"$custom\"" >> $rinfo
fi
echo "}" >> $rinfo

# service_manager
cp -r $src/staging/service_manager $target/service_manager

# Python library from tools to avoid files built specifically for MIPS
cp -r $src/tools/cppython/lib/* $target/service_manager/lib

#
# Override these files
#

# Disables standard BSD authentication
cp $ext/cpweb.py $target/service_manager/services/httpserver
rm $target/service_manager/services/httpserver/cpweb.pyc

# Customize web server ports, config store, and device store.
cp $ext/__init__.py $target/service_manager/services/httpserver
rm $target/service_manager/services/httpserver/__init__.pyc

# Derive these classes
cp $ext/wpc_config_store.py $target/service_manager
cp $ext/wpc_service_manager.py $target/service_manager
cp $ext/wpc_file_manager.py $target/service_manager

# Get locally built python interpreter (this means you should be running this
# build script on an OS compatible with your deployment target)
cp $src/tools/bin/cppython $target/service_manager/cppython

# Get firmware file
cp $src/coconut.bin $target/fw.bin

# Compress target
tarfile=wpc.tar.gz

cd $target_base
tar -czf $tarfile *
mv $tarfile ".."
cd ..

# Cleanup
rm -rf $target_base
