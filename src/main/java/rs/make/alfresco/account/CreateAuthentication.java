package rs.make.alfresco.account;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.alfresco.model.ContentModel;
import org.alfresco.query.PagingRequest;
import org.alfresco.query.PagingResults;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.security.MutableAuthenticationService;
import org.alfresco.service.cmr.security.PersonService;
import org.alfresco.service.namespace.QName;
import org.alfresco.util.Pair;
import org.apache.commons.validator.routines.EmailValidator;
import org.apache.log4j.Logger;
import org.json.simple.JSONArray;
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

public class CreateAuthentication extends DeclarativeWebScript {

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

	private final String PERSON_ASPECT_MODEL = "http://www.wbif.eu/model/document/1.0";
	private final String PERSON_ASPECT_NAME = "person";
	private final QName PERSON_ASPECT = QName.createQName( PERSON_ASPECT_MODEL , PERSON_ASPECT_NAME );

	private final String USER_ADMIN_AUTHORITY = "user-admins";
	private int responseThrowStatus = Status.STATUS_INTERNAL_SERVER_ERROR;
	private final String JSON_EMAIL_KEY = "email";
	private final String JSON_PASSWORD_KEY = "password";
	private final String JSON_NAME_KEY = "name";
	private final String JSON_ACTIVE_KEY = "active";
	private final String JSON_ORGANISATION_KEY = "organisation";
	private final String JSON_PERMISSION_KEY = "permission";
	private final String JSON_SPECIAL_PERMISSION_KEY = "special-permission";

	private final String SPECIAL_PERMISSION_TAG_PREFFIX = "special-permission--";
	private final String ORGANISATION_TAG_PREFFIX = "organisation--";
	private final String CONSUMER_SUFIX = "--consumer";
	private final String CONTRIBUTOR_SUFIX = "--contributor";
	private final String COORDINATOR_SUFIX = "--coordinator";

	private static Logger logger = Logger.getLogger( CreateAuthentication.class );

	@Override
	protected Map<String, Object> executeImpl( WebScriptRequest req , Status status , Cache cache ) {
		Map<String, Object> model = new HashMap<String, Object>();
		try{
			WebScript webscript = req.getServiceMatch().getWebScript();
			MakeMessage message = new MakeMessage( webscript );

			String authenticatedUserName = AuthenticationUtil.getFullyAuthenticatedUser();

			JSONObject requestJSON = makeCommonHelpers.validateJSONRequest( req , message , status );
			ArrayList<NodeRef> organisations = makeCommonHelpers.getNodes( requestJSON , JSON_ORGANISATION_KEY , message , status , false );

			AuthenticationUtil.setRunAsUserSystem();

			boolean userAuthorizedForSpecialPermissions = makeCommonHelpers.userIsSectionAdmin( authenticatedUserName , USER_ADMIN_AUTHORITY );
			boolean userAuthorized = userAuthorizedForSpecialPermissions || makeCommonHelpers.userIsOrganisationsAdmin( authenticatedUserName , organisations , COORDINATOR_SUFIX );
			if( !userAuthorized ){
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( authenticatedUserName );
				String errorMessage = message.get( "error.unauthorized" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_FORBIDDEN ) ) );
			}

			String email = makeCommonHelpers.getString( requestJSON , JSON_EMAIL_KEY , message , status , true );
			String password = makeCommonHelpers.getString( requestJSON , JSON_PASSWORD_KEY , message , status , false );
			if( password == null ) password = UUID.randomUUID().toString();
			String name = makeCommonHelpers.getString( requestJSON , JSON_NAME_KEY , message , status , true );
			Boolean active = makeCommonHelpers.getBooleanObj( requestJSON , JSON_ACTIVE_KEY , message , status , false );
			JSONArray permissions = makeCommonHelpers.getJSONArray( requestJSON , JSON_PERMISSION_KEY , message , status , false );
			JSONArray specialPermissions = makeCommonHelpers.getJSONArray( requestJSON , JSON_SPECIAL_PERMISSION_KEY , message , status , false );
			EmailValidator emailValidator = EmailValidator.getInstance( false );
			if( !emailValidator.isValid( email ) ) {
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( email );
				String errorMessage = message.get( "error.userNameIsNotEmail" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			if( checkIsEmailExisting( email ) || authenticationService.authenticationExists( email ) ) {
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( email );
				String errorMessage = message.get( "error.userNameAlreadyExisting" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
			}

			authenticationService.createAuthentication( email , password.toCharArray() );

			Map<QName, Serializable> user = new HashMap<QName, Serializable>();

			if( active == null || active.booleanValue() == false ) {
				authenticationService.setAuthenticationEnabled( email , false );
				user.put( ContentModel.PROP_ENABLED , false );
				user.put( ContentModel.PROP_ACCOUNT_LOCKED , true );
			}
			else{
				user.put( ContentModel.PROP_ENABLED , true );
				user.put( ContentModel.PROP_ACCOUNT_LOCKED , false );
			}

			user.put( ContentModel.PROP_USERNAME , email );
			user.put( ContentModel.PROP_FIRSTNAME , name );
			user.put( ContentModel.PROP_LASTNAME , "" );
			user.put( ContentModel.PROP_EMAIL , email );
			user.put( ContentModel.PROP_JOBTITLE , "" );

			NodeRef person = personService.createPerson( user );

			if( permissions != null ){
				for( Object permissionObj : permissions ){
					String permission = (String) permissionObj;
					if( permission.startsWith( ORGANISATION_TAG_PREFFIX ) && ( permission.endsWith( CONSUMER_SUFIX ) || permission.endsWith( CONTRIBUTOR_SUFIX ) || permission.endsWith( COORDINATOR_SUFIX ) ) )
						makeCommonHelpers.addTags( person , permissions , new Boolean( true ) );
				}
			}
			if( specialPermissions != null && userAuthorizedForSpecialPermissions ){
				for( Object permissionObj : specialPermissions ){
					String permission = (String) permissionObj;
					if( permission.startsWith( SPECIAL_PERMISSION_TAG_PREFFIX ) )
						makeCommonHelpers.addTags( person , specialPermissions , new Boolean( true ) );
				}
			}

			if( !nodeService.hasAspect( person , PERSON_ASPECT ) ) nodeService.addAspect( person , PERSON_ASPECT , null );

			AuthenticationUtil.setRunAsUser( authenticatedUserName );

			Gson gson = new Gson();
			model.put( "response", gson.toJson( nodeService.getProperties( person ) ) );
			ArrayList<String> args = new ArrayList<String>(1);
			args.add( email );
			String parsedMessage = message.get( "success.text" , args );
			model.put( "success", ( parsedMessage != null ) ? parsedMessage : "" );
		}
		catch( Exception e ) {
			try{
				logger.debug( "[" + CreateAuthentication.class.getName() + "] Error message: " + e.getMessage() );
				logger.debug( "[" + CreateAuthentication.class.getName() + "] Error cause: " + ( ( e.getCause() != null ) ? e.getCause().getMessage() : "" ) );
				logger.debug( "[" + CreateAuthentication.class.getName() + "] " , e );
				responseThrowStatus = ( e.getCause() != null ) ? Integer.parseInt( e.getCause().getMessage() , 10 ) : Status.STATUS_INTERNAL_SERVER_ERROR;
			}
			catch( Exception rtse ){
				logger.error( "[" + CreateAuthentication.class.getName() + "] " + rtse.getMessage() );
			}
			logger.error( "[" + CreateAuthentication.class.getName() + "] " + e.getMessage() );
			makeStatus.throwStatus( e.getMessage() , status , responseThrowStatus , CreateAuthentication.class );
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
