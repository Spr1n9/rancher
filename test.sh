cat << 'EOF' > run_long_endurance.sh
#!/bin/bash
HARBOR="registry-test.intsig.net"
PROJECT="bandwidth-test"
IMAGE_PREFIX="limit-test"
INTERFACE="eth0"
LOG_FILE="upload_long.csv"
ROUNDS=3  # 跑3轮
CONCURRENCY=10 # 保持10路并发（比较稳）

# --- 0. 清理环境 ---
echo ">>> [初始化] 清理残余..."
pkill -f "cat /sys/class/net" 2>/dev/null
docker image rm $(docker images | grep -E "bandwidth|static-test|limit-test" | awk '{print $3}') 2>/dev/null
docker system prune -f >/dev/null 2>&1

# --- 1. 启动全局监控 ---
echo "Timestamp,Mbps" > $LOG_FILE
echo ">>> 启动全程式网络监控..."
(
    T1=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)
    while true; do
        sleep 1
        T2=$(cat /sys/class/net/$INTERFACE/statistics/tx_bytes)
        NOW=$(date "+%H:%M:%S")
        DIFF=$((T2 - T1))
        SPEED=$(awk -v val=$DIFF 'BEGIN {printf "%.2f", val * 8 / 1000 / 1000}')
        echo "$NOW: $SPEED Mbps"
        echo "$NOW,$SPEED" >> $LOG_FILE
        T1=$T2
    done
) &
MONITOR_PID=$!

# --- 2. 开始波次进攻 ---
for (( r=1; r<=ROUNDS; r++ ))
do
    echo ""
    echo "============================================"
    echo ">>> 进入第 $r / $ROUNDS 轮压测 (Generation & Push)"
    echo "============================================"
    
    # 临时目录
    WORK_DIR="/juicefs-algorithm/temp_round_$r"
    mkdir -p $WORK_DIR

    # 2.1 生成镜像 (必须重新生成随机数据，否则Harbor会秒传)
    echo "   -> 正在制造 10 个全新镜像 (3GB)..."
    for i in $(seq 1 $CONCURRENCY); do
        SUB_DIR="$WORK_DIR/img_$i"
        mkdir -p $SUB_DIR
        # 生成 300MB 随机数据 (确保哈希值变动)
        dd if=/dev/urandom of=$SUB_DIR/data.bin bs=100M count=3 status=none
        
        echo "FROM alpine:latest" > $SUB_DIR/Dockerfile
        echo "COPY data.bin /tmp/random_data.bin" >> $SUB_DIR/Dockerfile
        
        # 标签带上轮次，防止混淆
        TAG="$HARBOR/$PROJECT/$IMAGE_PREFIX:r${r}_v${i}"
        docker build -t $TAG -f $SUB_DIR/Dockerfile $SUB_DIR >/dev/null
        
        # 删掉临时文件省空间
        rm -rf $SUB_DIR
    done
    rm -rf $WORK_DIR
    echo "   -> 镜像准备完毕，开始轰炸..."

    # 2.2并发推送
    PIDS=""
    for i in $(seq 1 $CONCURRENCY); do
        TAG="$HARBOR/$PROJECT/$IMAGE_PREFIX:r${r}_v${i}"
        (
            docker push $TAG >/dev/null 2>&1
            echo "      --> [轮次$r-镜像$i] 推送完成"
        ) &
        PIDS="$PIDS $!"
    done
    
    # 等待本轮结束
    wait $PIDS
    echo "   -> 第 $r 轮推送结束。"

    # 2.3 立即清理释放空间给下一轮
    echo "   -> [清理] 释放磁盘空间..."
    docker image rm $(docker images | grep "$IMAGE_PREFIX" | awk '{print $3}') 2>/dev/null
    docker system prune -f >/dev/null 2>&1
    
    # 稍微缓2秒
    sleep 2
done

# --- 3. 结束 ---
kill $MONITOR_PID
echo ""
echo ">>> 所有轮次结束！"
echo ">>> 结果统计 (去除生成镜像期间的低值，只看有流量的时段):"
awk -F',' '$2 > 10 {sum+=$2; count++} END {if (count > 0) printf "有效传输期间平均速度: %.2f Mbps\n", sum/count; else print "无有效数据"}' $LOG_FILE

EOF

chmod +x run_long_endurance.sh
./run_long_endurance.sh