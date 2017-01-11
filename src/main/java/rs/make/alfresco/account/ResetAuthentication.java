package rs.make.alfresco.account;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.alfresco.model.ContentModel;
import org.alfresco.query.PagingRequest;
import org.alfresco.query.PagingResults;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.MutableAuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.NamespaceService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.Pair;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.log4j.Logger;
import org.json.simple.JSONObject;
import org.springframework.extensions.webscripts.Cache;
import org.springframework.extensions.webscripts.DeclarativeWebScript;
import org.springframework.extensions.webscripts.Status;
import org.springframework.extensions.webscripts.WebScript;
import org.springframework.extensions.webscripts.WebScriptRequest;

import com.google.gson.Gson;

import rs.make.alfresco.common.message.MakeMessage;
import rs.make.alfresco.common.status.MakeStatus;
import rs.make.alfresco.common.webscripts.MakeCommonHelpers;

public class ResetAuthentication extends DeclarativeWebScript {

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

	protected MutableAuthenticationService authenticationService;
	public MutableAuthenticationService getAuthenticationService() {
		return authenticationService;
	}
	public void setAuthenticationService( MutableAuthenticationService authenticationService ) {
		this.authenticationService = authenticationService;
	}

	protected PersonService personService;
	public PersonService getPersonService() {
		return personService;
	}
	public void setPersonService( PersonService personService ) {
		this.personService = personService;
	}

	protected NodeService nodeService;
	public NodeService getNodeService() {
		return nodeService;
	}
	public void setNodeService( NodeService nodeService ) {
		this.nodeService = nodeService;
	}

	private final String REQUIRED_TOKEN_NAME = "requiredToken";
	private final QName REQUIRED_TOKEN = QName.createQName( NamespaceService.CONTENT_MODEL_1_0_URI , REQUIRED_TOKEN_NAME );
	private final String TOKEN_VALIDITY_NAME = "tokenValidity";
	private final QName TOKEN_VALIDITY = QName.createQName( NamespaceService.CONTENT_MODEL_1_0_URI , TOKEN_VALIDITY_NAME );

	private int responseThrowStatus = Status.STATUS_INTERNAL_SERVER_ERROR;
	private final String JSON_TOKEN_KEY = "token";
	private final String JSON_EMAIL_KEY = "email";
	private final String JSON_PASSWORD_KEY = "password";
	private final String JSON_NAME_KEY = "name";
	private final String JSON_ACTIVE_KEY = "active";

	private static Logger logger = Logger.getLogger( ResetAuthentication.class );

	@Override
	protected Map<String, Object> executeImpl( WebScriptRequest req , Status status , Cache cache ) {
		Map<String, Object> model = new HashMap<String, Object>();
		try{
			WebScript webscript = req.getServiceMatch().getWebScript();
			MakeMessage message = new MakeMessage( webscript );

			JSONObject requestJSON = makeCommonHelpers.validateJSONRequest( req , message , status );
			String token = makeCommonHelpers.getString( requestJSON , JSON_TOKEN_KEY , message , status , true );
			String email = makeCommonHelpers.getString( requestJSON , JSON_EMAIL_KEY , message , status , true );
			String password = makeCommonHelpers.getString( requestJSON , JSON_PASSWORD_KEY , message , status , true );
			String name = makeCommonHelpers.getString( requestJSON , JSON_NAME_KEY , message , status , false );
			Boolean active = makeCommonHelpers.getBooleanObj( requestJSON , JSON_ACTIVE_KEY , message , status , false );
			EmailValidator emailValidator = EmailValidator.getInstance( false );
			if( !emailValidator.isValid( email ) ) {
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( email );
				String errorMessage = message.get( "error.userNameIsNotEmail" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			AuthenticationUtil.setRunAsUserSystem();

			if( !checkIsEmailExisting( email ) || !authenticationService.authenticationExists( email ) ) {
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( email );
				String errorMessage = message.get( "error.userNameDoesNotExist" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			NodeRef person = personService.getPerson( email );
			if( person == null ){
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( email );
				String errorMessage = message.get( "error.personDoesNotExist" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			Date tokenValidity = (Date) nodeService.getProperty( person , TOKEN_VALIDITY );
			if( tokenValidity == null || tokenValidity.compareTo( new Date() ) < 0 ){
				String errorMessage = message.get( "error.invalidTokenValidity" , null );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}
			String requiredToken = (String) nodeService.getProperty( person , REQUIRED_TOKEN );
			if( requiredToken == null || !requiredToken.equals( token ) ){
				String errorMessage = message.get( "error.invalidToken" , null );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			authenticationService.setAuthentication( email , password.toCharArray() );

			if( active != null ) {
				authenticationService.setAuthenticationEnabled( email , active.booleanValue() );
				Map<QName, Serializable> user = new HashMap<QName, Serializable>();
				user.put( ContentModel.PROP_ENABLED , active.booleanValue() );
				user.put( ContentModel.PROP_ACCOUNT_LOCKED , !active.booleanValue() );
				personService.setPersonProperties( email , user );
			}

			if( name != null ){
				Map<QName, Serializable> user = new HashMap<QName, Serializable>();
				user.put( ContentModel.PROP_USERNAME , email );
				user.put( ContentModel.PROP_FIRSTNAME , name );
				user.put( ContentModel.PROP_LASTNAME , "" );
				user.put( ContentModel.PROP_EMAIL , email );
				user.put( ContentModel.PROP_JOBTITLE , "" );
				personService.setPersonProperties( email , user );
			}

			nodeService.setProperty( person , REQUIRED_TOKEN , null );
			nodeService.setProperty( person , TOKEN_VALIDITY , null );

			Map<QName, Serializable> properties = nodeService.getProperties( person );

			AuthenticationUtil.clearCurrentSecurityContext();

			Gson gson = new Gson();
			model.put( "response", gson.toJson( properties ) );
			ArrayList<String> args = new ArrayList<String>(1);
			args.add( email );
			String parsedMessage = message.get( "success.text" , args );
			model.put( "success", ( parsedMessage != null ) ? parsedMessage : "" );
		}
		catch( Exception e ) {
			try{
				logger.debug( "[" + ResetAuthentication.class.getName() + "] Error message: " + e.getMessage() );
				logger.debug( "[" + ResetAuthentication.class.getName() + "] Error cause: " + ( ( e.getCause() != null ) ? e.getCause().getMessage() : "" ) );
				logger.debug( "[" + ResetAuthentication.class.getName() + "] " , e );
				responseThrowStatus = ( e.getCause() != null ) ? Integer.parseInt( e.getCause().getMessage() , 10 ) : Status.STATUS_INTERNAL_SERVER_ERROR;
			}
			catch( Exception rtse ){
				logger.error( "[" + ResetAuthentication.class.getName() + "] " + rtse.getMessage() );
			}
			logger.error( "[" + ResetAuthentication.class.getName() + "] " + e.getMessage() );
			makeStatus.throwStatus( e.getMessage() , status , responseThrowStatus , ResetAuthentication.class );
			return null;
		}
		return model;
	}

	private boolean checkIsEmailExisting( String email ) throws Exception{
		boolean existing = false;

		List<QName> lookFor = new ArrayList<QName>(1);
		lookFor.add( ContentModel.PROP_EMAIL );
		List<Pair<QName,Boolean>> sortProps = new ArrayList<Pair<QName,Boolean>>(1);
		Pair<QName,Boolean> emailSort = new Pair<QName,Boolean>( ContentModel.PROP_EMAIL , true );
		sortProps.add( emailSort );
		PagingRequest pagingRequest = new PagingRequest( 2 );
		PagingResults<PersonService.PersonInfo> persons = personService.getPeople( email , lookFor , sortProps , pagingRequest );

		int resultSize = persons.getPage().size();
		if( resultSize > 0 ) existing = true;

		return existing;
	}
}
