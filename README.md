<img src="https://i.imgur.com/EZPrEEX.png" height="300">

## Flight Passport OAuth Server

A OAuth provider focused on UTM / U-Space that can be self hosted and used to issue JWT tokens for software UTM software like DSS, Registries, Remote ID Display providers etc. In addition you can use this as a OpenID Connect provider (OIDC) for your application providing identity services for your users.

## Why?

The upcoming standards being developed at ASTM, EuroCAE etc. on drones use JWT / OAuth 2.0 based tokens to exchange credentials and permissions. There are many open and closed sourced solutions available for issuing tokens. There are a few limitations to the current offerings:

- National Entities may or may not be interested in using private commercial companies for authentication and identity. Since this can be / is a national function, they would prefer to host the platform locally.
- OAuth / OpenID / Open ID Connect stack are a “general purpose” authentication and identity standard and the commercial solutions available price it very differently. Some charge by number of users, some charge by number of tokens / clients etc. All of this is not really suitable for UTM / U-Space operations.
- The Remote ID standard and demos use the `sub` and `aud` claim in a specific way that a number of commercial solutions do not support out-of-the-box. e.g. Azure does not support “scope” in Client Credentials grant, this is required per the Remote ID standard.
- On the [open source side](https://oauth.net/code/), a number of them are not totally ready or have very complex installation procedures or have too many features that make it bulky: e.g. user management. These make them unsuitable / overkill for the specific use-cases.

### Background

While there are many authentication and identity providers that support OAuth 2.0 and OpenID / OpenID Connect Credentials, all of them have some limitations in the context of U-Space / UTM. As of February 2020, OAuth 2.0 and JavaScript Web Token (JWTs) as a way to authenticate and issue credentials are parts of upcoming UTM / U-Space standards (e.g. DSS). Commercial service providers may or may not suffice for all cases, therefore this project is developed to enable maximum flexibility and still issue secure JWT tokens. This project can be deployed on any cloud service provider (national or international) and can be customized in any way to suit local UTM / U-Space needs.

## Running locally / Deployment
Refer to the [deployment](https://github.com/openutm/deployment) repository to see how you can deploy this server along with instructions and sample environment file.

## Technical Details

Flight Passport is a OAuth Provider that runs on Django and the fantastic [Authlib](https://authlib.org/) library and [Django OAuth Toolkit](https://github.com/jazzband/django-oauth-toolkit).

## Self-install

This is a Django project that uses Django and other opensource libraries.

### 1. Create a .env file

Download the `.passport.env.example` to `.env` and fill in appropriately. Create new key, follow instructions [here](https://github.com/openutm/deployment/blob/main/constructing_environment_files.md) for example.

### 2. Install Dependencies

Python 3 is required for this and install dependencies using `uv sync`. You will need to install `uv`, see instructions [here](https://docs.astral.sh/uv/#installation)

### 3. Create Initial Database

Use `python manage.py migrate` to create the initial database tables locally. It will use the default SQLite.

### 4. Create a Django administrator

Use `python manage.py createsuperuser` to create a administrator.

### 5. Set site name and domain

Run  `python manage.py initialize_db`

### 6. Start Server

Run  `python manage.py runserver`

### 7. Login to Administration interface and create a client

Go to `http://localhost:8000/admin` and login to the Django Admin inter

### 8. Make a Client Credentials request

Use a API client such as Postman or Insomnia to run a `client_credentials` request.

### 9. OIDC Grant

You can also implement a login / username password system, for an example see [OIDC Client](https://github.com/openutm-labs/flight_passport_oidc_client).

#### Image credit

[Passport Vectors by Vecteezy](https://www.vecteezy.com/free-vector/passport)
