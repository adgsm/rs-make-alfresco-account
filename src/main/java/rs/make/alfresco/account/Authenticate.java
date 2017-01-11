package rs.make.alfresco.account;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.alfresco.model.ContentModel;
import org.alfresco.query.PagingRequest;
import org.alfresco.query.PagingResults;
import org.alfresco.repo.security.authentication.AuthenticationException;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.security.AuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.Pair;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScript;
import org.springframework.extensions.webscripts.WebScriptRequest;

import rs.make.alfresco.common.message.MakeMessage;
import rs.make.alfresco.common.status.MakeStatus;
import rs.make.alfresco.common.webscripts.MakeCommonHelpers;

import org.apache.commons.validator.routines.EmailValidator;

public class Authenticate extends DeclarativeWebScript {

	protected MakeStatus makeStatus;
	public MakeStatus getMakeStatus() {
		return makeStatus;
	}
	public void setMakeStatus( MakeStatus makeStatus ) {
		this.makeStatus = makeStatus;
	}

	protected MakeCommonHelpers makeCommonHelpers;
	public MakeCommonHelpers getMakeCommonHelpers() {
		return makeCommonHelpers;
	}
	public void setMakeCommonHelpers( MakeCommonHelpers makeCommonHelpers ) {
		this.makeCommonHelpers = makeCommonHelpers;
	}

	protected AuthenticationService authenticationService;
	public AuthenticationService getAuthenticationService() {
		return authenticationService;
	}
	public void setAuthenticationService( AuthenticationService authenticationService ) {
		this.authenticationService = authenticationService;
	}

	protected PersonService personService;
	public PersonService getPersonService() {
		return personService;
	}
	public void setPersonService( PersonService personService ) {
		this.personService = personService;
	}

	private int responseThrowStatus = Status.STATUS_INTERNAL_SERVER_ERROR;
	private final String JSON_TOKEN_KEY = "token";
	private final String JSON_USER_NAME_KEY = "username";
	private final String JSON_PASSWORD_KEY = "password";

	private final String TOKEN_KEY = "token";
	private final String USERNAME_KEY = "username";

	private static Logger logger = Logger.getLogger( Authenticate.class );

	@Override
	protected Map<String, Object> executeImpl( WebScriptRequest req , Status status , Cache cache ) {
		Map<String, Object> model = new HashMap<String, Object>();
		try{
			WebScript webscript = req.getServiceMatch().getWebScript();
			MakeMessage message = new MakeMessage( webscript );

			JSONObject requestJSON = makeCommonHelpers.validateJSONRequest( req , message , status );
			String token = makeCommonHelpers.getString( requestJSON , JSON_TOKEN_KEY , message , status , false );
			String userName = makeCommonHelpers.getString( requestJSON , JSON_USER_NAME_KEY , message , status , false );
			userName = checkIsUserNameAnEmail( userName , message );
			if( userName != null ){
				String password = makeCommonHelpers.getString( requestJSON , JSON_PASSWORD_KEY , message , status , true );

				AuthenticationUtil.setRunAsUserSystem();
				boolean authenticationExist = authenticationService.authenticationExists( userName );
				if( authenticationExist ) authenticationService.invalidateUserSession( userName );
				AuthenticationUtil.clearCurrentSecurityContext();

				try{
					if( userName.equals( new String( "" ) ) ) throw new AuthenticationException( userName );
					authenticationService.authenticate( userName , password.toCharArray() );
					token = authenticationService.getCurrentTicket();
					logger.debug( "User \"" + userName + "\" has successfully authenticated." );
				}
				catch( AuthenticationException ae ){
					ArrayList<String> args = new ArrayList<String>(1);
					args.add( userName );
					String errorMessage = message.get( "error.unauthorizedUserNamePassword" , args );
					throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_UNAUTHORIZED ) ) );
				}
			}
			else if( token != null ){
				try{
					authenticationService.validate( token );
					userName = AuthenticationUtil.getFullyAuthenticatedUser();
					logger.debug( "Token \"" + token + "\" successfully validated for user \"" + userName + "\"." );
				}
				catch( AuthenticationException ae ){
					Map<String,String> authObj = authenticateAsGuest();
					token = authObj.get( TOKEN_KEY );
					userName = authObj.get( USERNAME_KEY );
				}
			}
			else{
				Map<String,String> authObj = authenticateAsGuest();
				token = authObj.get( TOKEN_KEY );
				userName = authObj.get( USERNAME_KEY );
			}

			model.put( "response", token );
			model.put( "username", userName );
			String parsedMessage = message.get( "success.text" , null );
			model.put( "success", ( parsedMessage != null ) ? parsedMessage : "" );
		}
		catch( Exception e ) {
			try{
				logger.debug( "[" + Authenticate.class.getName() + "] Error message: " + e.getMessage() );
				logger.debug( "[" + Authenticate.class.getName() + "] Error cause: " + ( ( e.getCause() != null ) ? e.getCause().getMessage() : "" ) );
				logger.debug( "[" + Authenticate.class.getName() + "] " , e );
				responseThrowStatus = ( e.getCause() != null ) ? Integer.parseInt( e.getCause().getMessage() , 10 ) : Status.STATUS_INTERNAL_SERVER_ERROR;
			}
			catch( Exception rtse ){
				logger.error( "[" + Authenticate.class.getName() + "] " + rtse.getMessage() );
			}
			logger.error( "[" + Authenticate.class.getName() + "] " + e.getMessage() );
			makeStatus.throwStatus( e.getMessage() , status , responseThrowStatus , Authenticate.class );
			return null;
		}
		return model;
	}

	private Map<String,String> authenticateAsGuest(){
		Map<String,String> authObj = new HashMap<String, String>(2);
		authenticationService.authenticateAsGuest();
		String token = authenticationService.getCurrentTicket();
		String userName = AuthenticationUtil.getFullyAuthenticatedUser();
		authObj.put( TOKEN_KEY , token );
		authObj.put( USERNAME_KEY , userName );
		logger.debug( "Continue running as \"" + userName + "\" (guest)." );
		return authObj;
	}

	private String checkIsUserNameAnEmail( String userName , MakeMessage message ) throws Exception{
		EmailValidator emailValidator = EmailValidator.getInstance( false );
		if( !emailValidator.isValid( userName ) ) return userName;

		AuthenticationUtil.setRunAsUserSystem();

		List<QName> lookFor = new ArrayList<QName>(1);
		lookFor.add( ContentModel.PROP_EMAIL );
		List<Pair<QName,Boolean>> sortProps = new ArrayList<Pair<QName,Boolean>>(1);
		Pair<QName,Boolean> emailSort = new Pair<QName,Boolean>( ContentModel.PROP_EMAIL , true );
		sortProps.add( emailSort );
		PagingRequest pagingRequest = new PagingRequest( 2 );
		PagingResults<PersonService.PersonInfo> persons = personService.getPeople( userName , lookFor , sortProps , pagingRequest );

		int resultSize = persons.getPage().size();
		if( resultSize > 1 ){
			ArrayList<String> args = new ArrayList<String>(2);
			args.add( userName );
			args.add( Integer.toString( resultSize ) );
			String errorMessage = message.get( "error.moreThanOnePersonRegisteredWIthThisEmail" , args );
			throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_UNAUTHORIZED ) ) );
		}
		else if( resultSize == 1 ){
			logger.debug( "Found matching user for email \"" + userName + "\"." );
			userName = persons.getPage().get( 0 ).getUserName();
		}

		AuthenticationUtil.clearCurrentSecurityContext();

		return userName;
	}
}
