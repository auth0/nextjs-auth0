docker build -t auth0-nextjs-01-login .
docker run --init -p 3000:3000 -p 3001:3001 -it auth0-nextjs-01-login
