package rs.make.alfresco.account;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.alfresco.model.ContentModel;
import org.alfresco.query.PagingRequest;
import org.alfresco.query.PagingResults;
import org.alfresco.repo.security.authentication.AuthenticationUtil;
import org.alfresco.service.cmr.repository.NodeRef;
import org.alfresco.service.cmr.repository.NodeService;
import org.alfresco.service.cmr.search.SearchService;
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

public class SetAuthentication extends DeclarativeWebScript {

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

	protected SearchService searchService;
	public SearchService getSearchService() {
		return searchService;
	}
	public void setSearchService( SearchService searchService ) {
		this.searchService = searchService;
	}

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
	private final String[] SUFIXES ={ CONSUMER_SUFIX , CONTRIBUTOR_SUFIX , COORDINATOR_SUFIX };

	private final String DEFAULT_ATTRIBUTE = "DEFAULT";
	private final String DEFAULT_ORGANISATIONS_ATTRIBUTE = "organizations";
	private final String PROPERTY_KEY = "property";
	private final String CONTAINER_KEY = "container";

	private static Logger logger = Logger.getLogger( SetAuthentication.class );

	@SuppressWarnings("unchecked")
	@Override
	protected Map<String, Object> executeImpl( WebScriptRequest req , Status status , Cache cache ) {
		Map<String, Object> model = new HashMap<String, Object>();
		try{
			WebScript webscript = req.getServiceMatch().getWebScript();
			MakeMessage message = new MakeMessage( webscript );

			String authenticatedUserName = AuthenticationUtil.getFullyAuthenticatedUser();

			JSONObject requestJSON = makeCommonHelpers.validateJSONRequest( req , message , status );
			ArrayList<NodeRef> organisations = makeCommonHelpers.getNodes( requestJSON , JSON_ORGANISATION_KEY , message , status , false );
			String email = makeCommonHelpers.getString( requestJSON , JSON_EMAIL_KEY , message , status , true );

			AuthenticationUtil.setRunAsUserSystem();

			NodeRef organisationsContainer = getOrganisationsContainer();
			if( organisationsContainer == null ){
				String errorMessage = message.get( "error.noOrganisationsContainerFound" , null );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_INTERNAL_SERVER_ERROR ) ) );
			}

			if( organisations == null ) {
				ArrayList<NodeRef> organisationNodes = new ArrayList<NodeRef>();
				ArrayList<String> organisationsTagsArr = makeCommonHelpers.getFilteredUserTags( authenticatedUserName , ORGANISATION_TAG_PREFFIX , SUFIXES , new Boolean( false ) );
				for( String organisationTag : organisationsTagsArr ){
					String organisationName = organisationTag.replaceFirst( ORGANISATION_TAG_PREFFIX , "" );
					NodeRef organisationNode = nodeService.getChildByName( organisationsContainer , ContentModel.ASSOC_CONTAINS , organisationName );
					if( organisationNode != null ) organisationNodes.add( organisationNode );
				}
				if( !organisationNodes.isEmpty() ) {
					organisations = new ArrayList<NodeRef>();
					organisations.addAll( organisationNodes );
				}
			}

			ArrayList<String> existingOrgs = makeCommonHelpers.getFilteredUserTags( email , ORGANISATION_TAG_PREFFIX , new String[] {} );
			ArrayList<NodeRef> existingOrgNodes = new ArrayList<NodeRef>();
			for( String existingOrg : existingOrgs ){
				String existingOrgName = existingOrg.replaceFirst( ORGANISATION_TAG_PREFFIX , "" ).replaceAll( CONSUMER_SUFIX , "" ).replaceAll( CONTRIBUTOR_SUFIX , "" ).replaceAll( COORDINATOR_SUFIX , "" );
				NodeRef existingOrgNode = nodeService.getChildByName( organisationsContainer , ContentModel.ASSOC_CONTAINS , existingOrgName );
				if( existingOrgNode != null ) existingOrgNodes.add( existingOrgNode );
			}

			ArrayList<NodeRef> fullSetOrgNodes = new ArrayList<NodeRef>();
			fullSetOrgNodes.addAll( existingOrgNodes );
			fullSetOrgNodes.addAll( organisations );

			boolean userAuthorizedForSpecialPermissions = makeCommonHelpers.userIsSectionAdmin( authenticatedUserName , USER_ADMIN_AUTHORITY );
			boolean userIsSelf = ( email.equals( authenticatedUserName ) );
			boolean userIsAnyOrganisationCoordinator = makeCommonHelpers.userIsOrganisationsAdmin( authenticatedUserName , fullSetOrgNodes , COORDINATOR_SUFIX , true );
			boolean userAuthorized = userIsSelf || userAuthorizedForSpecialPermissions || userIsAnyOrganisationCoordinator;
			boolean userIsAllOrganisationsCoordinator = makeCommonHelpers.userIsOrganisationsAdmin( authenticatedUserName , existingOrgNodes , COORDINATOR_SUFIX );
			boolean userFullyAuthorized = userIsSelf || userAuthorizedForSpecialPermissions || userIsAllOrganisationsCoordinator;
			if( !userAuthorized ){
				ArrayList<String> args = new ArrayList<String>(1);
				args.add( authenticatedUserName );
				String errorMessage = message.get( "error.unauthorized" , args );
				throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_FORBIDDEN ) ) );
			}

			String password = makeCommonHelpers.getString( requestJSON , JSON_PASSWORD_KEY , message , status , false );
			String name = makeCommonHelpers.getString( requestJSON , JSON_NAME_KEY , message , status , false );
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

			if( userFullyAuthorized == true ){
				if( password != null ) authenticationService.setAuthentication( email , password.toCharArray() );
	
				if( active != null ) {
					authenticationService.setAuthenticationEnabled( email , active.booleanValue() );
					Map<QName, Serializable> user = new HashMap<QName, Serializable>();
					user.put( ContentModel.PROP_ENABLED , active.booleanValue() );
					user.put( ContentModel.PROP_ACCOUNT_LOCKED , !active.booleanValue() );
					personService.setPersonProperties( email , user );
				}
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

			if( permissions != null && ( userIsAnyOrganisationCoordinator == true || userAuthorizedForSpecialPermissions == true ) ){
				JSONArray permissionArr = new JSONArray();
				for( Object permissionObj : permissions ){
					String permission = (String) permissionObj;
					if( permission.startsWith( ORGANISATION_TAG_PREFFIX ) && ( permission.endsWith( CONSUMER_SUFIX ) || permission.endsWith( CONTRIBUTOR_SUFIX ) || permission.endsWith( COORDINATOR_SUFIX ) ) ){
						String permissionOrgnisation = permission.replaceFirst( ORGANISATION_TAG_PREFFIX , "" ).replaceAll( CONSUMER_SUFIX , "" ).replaceAll( CONTRIBUTOR_SUFIX , "" ).replaceAll( COORDINATOR_SUFIX , "" );
						NodeRef permissionOrgnisationNode = nodeService.getChildByName( organisationsContainer , ContentModel.ASSOC_CONTAINS , permissionOrgnisation );
						ArrayList<NodeRef> permissionOrgnisations = new ArrayList<NodeRef>(1);
						if( permissionOrgnisationNode != null ) permissionOrgnisations.add( permissionOrgnisationNode );
						boolean canChangePermissions = userAuthorizedForSpecialPermissions || makeCommonHelpers.userIsOrganisationsAdmin( authenticatedUserName , permissionOrgnisations , COORDINATOR_SUFIX );
						permissionOrgnisations = null;
						if( canChangePermissions == true ) {
							permissionArr.add( permission );
						}
						else{
							for( String existingTag : existingOrgs ){
								boolean existingTagMatch = existingTag.contains( ORGANISATION_TAG_PREFFIX + permissionOrgnisation );
								if( existingTagMatch == true ){
									if( permissionArr.indexOf( existingTag ) == -1 ) permissionArr.add( existingTag );
									break;
								}
							}
						}
					}
				}
				for( String existingTag : existingOrgs ){
					boolean orgTagMatch = existingTag.startsWith( ORGANISATION_TAG_PREFFIX ) && ( existingTag.endsWith( CONSUMER_SUFIX ) || existingTag.endsWith( CONTRIBUTOR_SUFIX ) || existingTag.endsWith( COORDINATOR_SUFIX ) );
					if( orgTagMatch && permissionArr.indexOf( existingTag ) == -1 ){
						String org = existingTag.replaceFirst( ORGANISATION_TAG_PREFFIX , "" ).replaceAll( CONSUMER_SUFIX , "" ).replaceAll( CONTRIBUTOR_SUFIX , "" ).replaceAll( COORDINATOR_SUFIX , "" );
						NodeRef orgNode = nodeService.getChildByName( organisationsContainer , ContentModel.ASSOC_CONTAINS , org );
						ArrayList<NodeRef> orgs = new ArrayList<NodeRef>(1);
						if( orgNode != null ) orgs.add( orgNode );
						boolean noPermissions = !userAuthorizedForSpecialPermissions && !makeCommonHelpers.userIsOrganisationsAdmin( authenticatedUserName , orgs , COORDINATOR_SUFIX );
						orgs = null;
						if( noPermissions == true ){
							permissionArr.add( existingTag );
						}
					}
				}
				if( permissionArr.size() > 0 ){
					makeCommonHelpers.addTags( person , permissionArr , new Boolean( true ) );
				}
				else{
					String errorMessage = message.get( "error.userMustBelongToAtLeastOneOrganisations" , null );
					throw new Exception( errorMessage , new Throwable( String.valueOf( Status.STATUS_BAD_REQUEST ) ) );
				}
			}
			if( specialPermissions != null && userAuthorizedForSpecialPermissions == true ){
				if( specialPermissions.size() > 0 ){
					for( Object permissionObj : specialPermissions ){
						String permission = (String) permissionObj;
						if( permission.startsWith( SPECIAL_PERMISSION_TAG_PREFFIX ) )
							makeCommonHelpers.addTags( person , specialPermissions , new Boolean( true ) );
					}
				}
				else{
					makeCommonHelpers.removeTagsWithPrefix( person , SPECIAL_PERMISSION_TAG_PREFFIX );
				}
			}

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
				logger.debug( "[" + SetAuthentication.class.getName() + "] Error message: " + e.getMessage() );
				logger.debug( "[" + SetAuthentication.class.getName() + "] Error cause: " + ( ( e.getCause() != null ) ? e.getCause().getMessage() : "" ) );
				logger.debug( "[" + SetAuthentication.class.getName() + "] " , e );
				responseThrowStatus = ( e.getCause() != null ) ? Integer.parseInt( e.getCause().getMessage() , 10 ) : Status.STATUS_INTERNAL_SERVER_ERROR;
			}
			catch( Exception rtse ){
				logger.error( "[" + SetAuthentication.class.getName() + "] " + rtse.getMessage() );
			}
			logger.error( "[" + SetAuthentication.class.getName() + "] " + e.getMessage() );
			makeStatus.throwStatus( e.getMessage() , status , responseThrowStatus , SetAuthentication.class );
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

	private NodeRef getOrganisationsContainer(){
		NodeRef organisationsContainer = null;
		Serializable[] keys = new Serializable[] { DEFAULT_ATTRIBUTE };
		JSONArray defaults = makeCommonHelpers.getAttribute( keys );
		for( Object orgDef : defaults ){
			JSONObject entry = (JSONObject) orgDef;
			if( ( (String) entry.get( PROPERTY_KEY ) ).equals( DEFAULT_ORGANISATIONS_ATTRIBUTE ) ) {
				String organisationsContainerNodeRef = (String) entry.get( CONTAINER_KEY );
				organisationsContainer = new NodeRef( organisationsContainerNodeRef );
				break;
			}
		}
		return organisationsContainer;
	}
}
