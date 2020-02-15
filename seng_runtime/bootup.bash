# Should be run after Container has been created

pushd sgx-ra-tls
# socat tunnel to aesmd required to sgx enclaves
socat -t10 TCP-LISTEN:1234,bind=127.0.0.1,reuseaddr,fork,range=127.0.0.0/8 UNIX-CLIENT:/var/run/aesmd/aesm.socket &
popd

# for /etc/localtime
sudo apt install tzdata

# oh-my-zsh
#sh -c "$(wget https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh -O -)"
