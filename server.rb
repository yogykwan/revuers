require 'sinatra'
require 'octokit'
require 'dotenv/load' # Manages environment variables
require 'json'
require 'openssl' # Verifies the webhook signature
require 'jwt' # Authenticates a GitHub App
require 'time' # Gets ISO 8601 representation of a Time object
require 'logger' # Logs debug statements

set :port, 3000
set :bind, '0.0.0.0'


# This is code to create a GitHub App server.
# You can read more about GitHub Apps here: # https://developer.github.com/apps/
#
# This code is a Sinatra app, for two reasons:
#   1. Because the app will require a landing page for installation.
#   2. To easily handle webhook events.

class GHAapp < Sinatra::Application

  # Expects that the private key in PEM format. Converts the newlines
  PRIVATE_KEY = OpenSSL::PKey::RSA.new(ENV['GITHUB_PRIVATE_KEY'].gsub('\n', "\n"))

  # Your registered app must have a secret set. The secret is used to verify
  # that webhooks are sent by GitHub.
  WEBHOOK_SECRET = ENV['GITHUB_WEBHOOK_SECRET']

  # The GitHub App's identifier (type integer) set when registering an app.
  APP_IDENTIFIER = ENV['GITHUB_APP_IDENTIFIER']

  # Turn on Sinatra's verbose logging during development
  configure :development do
    set :logging, Logger::DEBUG
  end


  # Before each request to the `/event_handler` route
  before '/event_handler' do
    get_payload_request(request)
    verify_webhook_signature
    authenticate_app
    # Authenticate the app installation in order to run API operations
    authenticate_installation(@payload)
  end


  post '/event_handler' do

    case request.env['HTTP_X_GITHUB_EVENT']

      when 'pull_request'
        if @payload['action'] === 'opened'
          handle_pr_opened_event(@payload)
        end

      when 'issues'
        if @payload['action'] === 'opened'
          handle_issue_opened_event(@payload)
        end

    end

    200 # success status
  end


  helpers do

    # When a pull request is opened, add reviewers and projects
    def handle_issue_opened_event(payload)
      labels = payload['issue']['labels']
      repo = payload['repository']['name']
      if repo === 'Admin'
        if labels.length > 0 and labels[0]['name'] === 'enhancement'
          create_dashboards(payload)
        else
          get_report(payload)
        end
      end
    end

    # Get progress for all students
    def get_report(payload)
      report = []
      org = payload['repository']['owner']['login']
      dashboards = @installation_client.organization_projects(org)
      for dashboard in dashboards
        row = dashboard['name']
        columns = @installation_client.project_columns(dashboard['id'])
        for column in columns
          cards = @installation_client.column_cards(column['id'])
          row += ',' + cards.length.to_s
        end
        report |= [row]
      end
      report = report.join("\n")
      output_report(payload, report)
    end

    # Output progress report in issue comment with .csv format
    def output_report(payload, report)
      repo = payload['repository']['full_name']
      issue_number = payload['issue']['number']
      @installation_client.add_comment(repo, issue_number, report)
    end

    # Create dashboards for all students
    def create_dashboards(payload)
      org = payload['repository']['owner']['login']
      members = @installation_client.organization_members(org).map {|x| x['login']}
      for member in members
        dashboard = @installation_client.create_org_project(org, member)
        columns = ['In progress', 'Review in progress', 'Reviewer approved', 'Done']
        for column in columns
          @installation_client.create_project_column(dashboard['id'], column)
        end
      end
    end

    # When a pull request is opened, add reviewers and projects
    def handle_pr_opened_event(payload)
      reviewers = get_reviewers(payload)
      add_reviewers(payload, reviewers)
      add_projects(payload, reviewers)
    end

    # Get n reviewers for a pull request
    def get_reviewers(payload, n = 1)
      org = payload['repository']['owner']['login']
      members = @installation_client.organization_members(org).map {|x| x['login']}
      owner = payload['pull_request']['user']['login']
      if n > members.length - 1
        n = members.length - 1
      end
      members = members.concat(members)
      index = members.index(owner)
      return members.slice(index + 1, n)
    end

    # Add reviewers for a pull request
    def add_reviewers(payload, reviewers)
      repo = payload['pull_request']['base']['repo']['full_name']
      pr_number = payload['number']
      @installation_client.request_pull_request_review(repo, pr_number, reviewers: reviewers)
    end

    # Add projects for a pull request
    def add_projects(payload, reviewers)
      org = payload['repository']['owner']['login']
      projects = @installation_client.org_projects(org)
      pr_id = payload['pull_request']['id']
      for reviewer in reviewers do
        for project in projects do
          if reviewer === project['name']
            columns = @installation_client.project_columns(project['id'])
            for column in columns do
              if column['name'] === 'In progress'
                @installation_client.create_project_card(column['id'], content_id: pr_id, content_type: 'PullRequest')
              end
            end
            break
          end
        end
      end
    end

    # Saves the raw payload and converts the payload to JSON format
    def get_payload_request(request)
      # request.body is an IO or StringIO object
      # Rewind in case someone already read it
      request.body.rewind
      # The raw text of the body is required for webhook signature verification
      @payload_raw = request.body.read
      begin
        @payload = JSON.parse @payload_raw
      rescue => e
        fail "Invalid JSON (#{e}): #{@payload_raw}"
      end
    end

    # Instantiate an Octokit client authenticated as a GitHub App.
    # GitHub App authentication requires that you construct a
    # JWT (https://jwt.io/introduction/) signed with the app's private key,
    # so GitHub can be sure that it came from the app an not altererd by
    # a malicious third party.
    def authenticate_app
      payload = {
          # The time that this JWT was issued, _i.e._ now.
          iat: Time.now.to_i,

          # JWT expiration time (10 minute maximum)
          exp: Time.now.to_i + (10 * 60),

          # Your GitHub App's identifier number
          iss: APP_IDENTIFIER
      }

      # Cryptographically sign the JWT.
      jwt = JWT.encode(payload, PRIVATE_KEY, 'RS256')

      # Create the Octokit client, using the JWT as the auth token.
      @app_client ||= Octokit::Client.new(bearer_token: jwt)
    end

    # Instantiate an Octokit client, authenticated as an installation of a
    # GitHub App, to run API operations.
    def authenticate_installation(payload)
      @installation_id = payload['installation']['id']
      @installation_token = @app_client.create_app_installation_access_token(@installation_id)[:token]
      @installation_client = Octokit::Client.new(bearer_token: @installation_token)
    end

    # Check X-Hub-Signature to confirm that this webhook was generated by
    # GitHub, and not a malicious third party.
    #
    # GitHub uses the WEBHOOK_SECRET, registered to the GitHub App, to
    # create the hash signature sent in the `X-HUB-Signature` header of each
    # webhook. This code computes the expected hash signature and compares it to
    # the signature sent in the `X-HUB-Signature` header. If they don't match,
    # this request is an attack, and you should reject it. GitHub uses the HMAC
    # hexdigest to compute the signature. The `X-HUB-Signature` looks something
    # like this: "sha1=123456".
    # See https://developer.github.com/webhooks/securing/ for details.
    def verify_webhook_signature
      their_signature_header = request.env['HTTP_X_HUB_SIGNATURE'] || 'sha1='
      method, their_digest = their_signature_header.split('=')
      our_digest = OpenSSL::HMAC.hexdigest(method, WEBHOOK_SECRET, @payload_raw)
      halt 401 unless their_digest == our_digest

      # The X-GITHUB-EVENT header provides the name of the event.
      # The action value indicates the which action triggered the event.
      logger.debug "---- received event #{request.env['HTTP_X_GITHUB_EVENT']}"
      logger.debug "----    action #{@payload['action']}" unless @payload['action'].nil?
    end

  end

  # Finally some logic to let us run this server directly from the command line,
  # or with Rack. Don't worry too much about this code. But, for the curious:
  # $0 is the executed file
  # __FILE__ is the current file
  # If they are the same—that is, we are running this file directly, call the
  # Sinatra run method
  run! if __FILE__ == $0
end
