#!/bin/bash

curl --retry 5 --retry-delay 2 --max-time 20 -L -O https://github.com/Delta-Kronecker/WarpGenerator/releases/download/0.1.1/termux-arm64.tar.gz && mkdir -p ~/warp-generator && tar -xzf termux-arm64.tar.gz -C ~/warp-generator && rm termux-arm64.tar.gz && chmod +x ~/warp-generator/termux-arm64/WarpGenerator && chmod +x ~/warp-generator/termux-arm64/wgcf && chmod +x ~/warp-generator/termux-arm64/core/xray && echo "alias w='cd ~/warp-generator/termux-arm64 && ./WarpGenerator'" >> ~/.bashrc && source ~/.bashrc
