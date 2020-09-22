version=$1

echo "=======gateway======="

mvn clean install -Dmaven.test.skip=true

docker build -f docker/dev.Dockerfile -t 192.168.10.124:8889/public/gateway:"${version}" .
docker push 192.168.10.124:8889/public/gateway:"${version}"
docker rmi -f 192.168.10.124:8889/public/gateway:"${version}"

#docker run -d -p 9771:8080 --name gateway1 --hostname gateway1 --network cloud-demo 192.168.10.124:8889/public/gateway:latest