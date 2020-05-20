.PHONY: view_dev view_prod prepare_data dev deploy_dev deploy_prod make_certs add_hosts add_cert_macos configure_laptop_macos

view_dev:
	kustomize build k8s/dev

view_prod:
	kustomize build k8s/prod

prepare_data:
	@echo "Preparing /tmp/with-apollo-hasura-ssr/data for data storage across k8s Pods"
	mkdir -p /tmp/with-apollo-hasura-ssr/data

docker_build:
	docker build . -t docker.io/logary/with-apollo-hasura-ssr

dev: prepare_data
	@echo "Using Skaffold to create a development environment (very similar to prod)"
	skaffold dev

deploy_dev_apply: prepare_data
	kustomize build k8s/dev | kubectl apply -f -
	
deploy_dev: deploy_dev_apply dev

deploy_prod:
	kustomize build k8s/dev | kubectl apply -f -



make_cert:
	(cd k8s/certs && ./create-test)

add_hosts:
	grep example.test /etc/hosts >/dev/null || \
		echo "127.0.0.1 api.example.test example.test" | sudo tee -a /etc/hosts

add_cert_macos:
	sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain k8s/certs/ca/ca.pem

configure_laptop_macos: make_cert add_hosts add_cert_macos
