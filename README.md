## Install

To run the code, make sure you have [Bundler](http://gembundler.com/) installed; then enter `bundle install` on the command line.

## Set environment variables

1. Add your GitHub App's private key, app ID, and webhook secret to the `.env` file.

## Run the server

1. Start webhook `smee --url https://smee.io/JYiHWxUEn038fj --path /event_handler --port 3000`. 
2. Run `ruby server.rb` on the command line.
3. View the default Sinatra app at `localhost:3000`.
