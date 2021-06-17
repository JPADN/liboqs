echo -e "Where should I install OQS-OpenSSL (absolute path):\n"
read OPENSSL_DIR

# OPENSSL_DIR=~/projects/labsec/labsec_gitlab/oqs_openssl_maker/openssl

CECIES_DIR=../lib/cecies
MAKEFILE_=integration_files/Makefile
CURRENT_DIR=$PWD

# ---------------------------------- LIBOQS ---------------------------------- #

cd ../build
cmake -GNinja -DCMAKE_INSTALL_PREFIX=${OPENSSL_DIR}/oqs ..
ninja install
cd ../${CURRENT_DIR}

# ---------------------------------- OPENSSL --------------------------------- #

sudo apt install cmake gcc libtool libssl-dev make ninja-build git

git clone --single-branch --branch OQS-OpenSSL_1_1_1-stable https://github.com/open-quantum-safe/openssl.git ${OPENSSL_DIR}

${OPENSSL_DIR}/Configure no-shared linux-x86_64 -lm

# Alterar Makefile
rm ${OPENSSL_DIR}/Makefile
cp ${MAKEFILE_} ${OPENSSL_DIR}

# Importar CECIES
bash ${CECIES_DIR}/build.sh
cp ${CECIES_DIR}/build/cecies/bin/release/{libcecies.so,libcecies.so.4,libcecies.so.4.0.0} ${OPENSSL_DIR}/oqs/lib

cd ${OPENSSL_DIR}
make