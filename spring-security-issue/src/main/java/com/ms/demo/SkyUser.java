package com.ms.demo;

import com.fasterxml.jackson.annotation.JsonIgnore;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;



public class SkyUser implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of();
    }

    @Override
    public String getPassword() {
        return "";
    }

    @Override
    public String getUsername() {
        return "";
    }

  /*  private static final long serialVersionUID = 1L;
    private static final List<SkyUserRole> blankRoles
            = Collections.unmodifiableList(new ArrayList<>(0));
    private static final List<SkyUserAclAttribute> blankAttributes
            = Collections.unmodifiableList(new ArrayList<>(0));
    private  final Logger logger = LoggerFactory.getLogger(getClass());

    private int id;
    private String username;
    private String firstName;
    private String lastName;
    private String email;
    private boolean accountExpired = false;
    private boolean accountLocked = false;
    private boolean credentialsExpired = false;
    private boolean enabled = true;
    private String password;
    private String salt;
    private List<SkyUserRole> roles;
    private List<SkyUserAclAttribute> aclAttributes;
    @JsonIgnore
    private Set<GrantedAuthority> authorities;

    // SKY Core Specific fields starts here
    //private User user;
    private Timestamp dynamicTokenValidUpto;
    private SkyUserDevice userDevice;
    // SKY Core Specific fields ends here

    *//**
     * Returns all the network ids associated with this user.
     *
     * @return Collection of Netweork Ids associated with this user.
     *//*
    @JsonIgnore
    public Collection<Integer> getNetworkIds() {
        return getAreaIds(SkyAdminArea.NETWORK);
    }

    public Collection<Integer> getAreaIds(SkyAdminArea area) {
        return getRoles()
                .stream()
                .filter(ur -> ur.getAdminArea()!=null && ur.getAdminArea().equals(area))
                .map(SkyUserRole::getAdminAreaId)
                .collect(Collectors.toList());
    }

    public int getId() {
        return id;
    }

    public void setId(int id) {
        this.id = id;
    }

    public void setFirstName(String firstName) {
        this.firstName = firstName;
    }

    public void setLastName(String lastName) {
        this.lastName = lastName;
    }

    public String getEmail() {
        return email;
    }

    public void setEmail(String email) {
        this.email = email;
    }

    @JsonIgnore
    public List<SkyAdminArea> getAdminAreas() {

        return getRoles().stream()
                .filter(r -> r.getAdminArea() != null)
                .map(r -> r.getAdminArea())
                .collect(Collectors.toList());
    }
    *//*
     * Returns all the enterprise ids associated with this user.
     *
     * @return Collection of enterprise Ids associated with this user.
     *//*
    @JsonIgnore
    public Collection<Integer> getEnterpriseIds() {
        return getAreaIds(SkyAdminArea.ENTERPRISE);
    }

    @JsonIgnore
    public Collection<Integer> getLocationIds() {
        return getAreaIds(SkyAdminArea.LOCATION);
    }

    @JsonIgnore
    public Collection<Integer> getChargerIds() {
        return getAreaIds(SkyAdminArea.CHARGER);
    }

    @JsonIgnore
    public Collection<Integer> getChargerGroupIds() {
        return getAreaIds(SkyAdminArea.CHARGER_GROUP);
    }

    @JsonIgnore
    public Collection<Integer> getManufacturerIds() {
        return getAreaIds(SkyAdminArea.MANUFACTURER);
    }

    *//**
     * Does this user has ANY role which permit this user
     * access to entire SKY application?
     *
     * @return true if this user has any role on SKY admin area, false otherwise.
     *//*
    @JsonIgnore
    public boolean hasSkyWideAccess() {
        return getRoles(SkyAdminArea.SKY).size() > 0;
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }


    private List<String> getStringAuthorities() {
        return getAuthorities().stream().map(a -> a.toString()).collect(Collectors.toList());
    }
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        if (authorities == null)
            buildAuthorities();
        return authorities;
    }

    public boolean hasAuthority(String authority) {
        return (getStringAuthorities().contains(authority));
    }

    public boolean hasAnyAuthority(String ...authorities) {
        for (var authority: authorities) {
            if (getStringAuthorities().contains(authority)) {
                return true;
            }
        }
        return false;
    }

    private synchronized void buildAuthorities() {
        if (authorities != null)
            return;
        Set<String> strAuths = new HashSet<>();
        getRolesText().forEach(ar -> {
            if (ar == null || ar.isEmpty())
                return;
            if (ar.startsWith("ROLE_"))
                strAuths.add(ar);
            else
                strAuths.add("ROLE_" + ar);
        });
        strAuths.addAll(getPermissions());
        Set<GrantedAuthority> auths = strAuths.stream()
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toSet());
        authorities = Collections.unmodifiableSet(auths);
        if (logger.isTraceEnabled())
            logger.trace("Built Authorities: {}", authorities);
    }

    @JsonIgnore
    @Override
    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonExpired() {
        return !accountExpired;
    }

    @JsonIgnore
    @Override
    public boolean isAccountNonLocked() {
        return !accountLocked;
    }

    @JsonIgnore
    @Override
    public boolean isCredentialsNonExpired() {
        return !credentialsExpired;
    }

    @Override
    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public boolean isAccountExpired() {
        return accountExpired;
    }

    public void setAccountExpired(boolean accountExpired) {
        this.accountExpired = accountExpired;
    }

    public boolean isAccountLocked() {
        return accountLocked;
    }

    public void setAccountLocked(boolean accountLocked) {
        this.accountLocked = accountLocked;
    }

    public boolean isCredentialsExpired() {
        return credentialsExpired;
    }

    public void setCredentialsExpired(boolean credentialsExpired) {
        this.credentialsExpired = credentialsExpired;
    }

    @JsonIgnore
    public String getSalt() {
        return salt;
    }

    public void setSalt(String salt) {
        this.salt = salt;
    }

    *//**
     * Add permission directly associated with the user. This method
     * <b>MUST</b> be called after all roles have been populated.
     *
     * @param permission  name of the direct permission
     * @param areaStr     admin area name
     * @param adminAreaId admin area id
     * @param excluded    should this permission be excluded instead of inclusion
     *//*
    public void addUserPermission(String permission, String areaStr, int adminAreaId, boolean excluded) {
        List<SkyUserRole> matchingRole = getRoles(areaStr, adminAreaId);
        if (matchingRole == null) {
            SkyUserRole newRole = new SkyUserRole();
            newRole.setAdminArea(SkyAdminArea.valueOf(areaStr));
            newRole.setAdminAreaId(adminAreaId);
            if (roles == null)
                roles = new ArrayList<>();
            roles.add(newRole);
            matchingRole = Collections.singletonList(newRole);
        }
        addUserPermission(matchingRole, permission, excluded);
    }

    private void addUserPermission(List<SkyUserRole> roles, String permission, boolean excluded) {
        roles.forEach(r -> {
            if (excluded)
                r.addExcludedPermission(permission);
            else
                r.addIncludedPermission(permission);
        });
    }

    public List<SkyUserRole> getRoles() {
        if (roles == null)
            return blankRoles;
        return roles;
    }

    public void setRoles(List<SkyUserRole> roles) {
        this.roles = roles;
    }

    public List<SkyUserAclAttribute> getAclAttributes() {
        if (aclAttributes == null)
            return blankAttributes;
        return aclAttributes;
    }

    public void setAclAttributes(List<SkyUserAclAttribute> aclAttributes) {
        this.aclAttributes = aclAttributes;
    }

    *//**
     * Fetch ALL ACL attributes matching with givne name. There could possibly
     * be multiple attributes with same name, possibly with different permission
     * and/or admin area details. Use them appropriately in your logic.
     *
     * @param attributeName name of the attribute for which values are required
     * @return List of attribute matching with given name.
     *//*
    public List<SkyUserAclAttribute> getAclAttributes(String attributeName) {
        return getAclAttributes()
                .stream()
                .filter(x -> x.getName().equals(attributeName))
                .collect(Collectors.toList());
    }

    *//**
     * A convenient method for {@link #getAclAttributes(String)} giving you first matching
     * attribute if found, null otherwise. It's always advised to call {@link #getAclAttributes(String)}
     * in case you know there could be multiple values and use them appropriately instead.
     *
     * @param attributeName name of the attribute for which value is required
     * @return Attribute object if found, null otherwise
     * @see #getAclAttribute(String)
     *//*
    public SkyUserAclAttribute getAclAttribute(String attributeName) {
        List<SkyUserAclAttribute> filtered = getAclAttributes(attributeName);
        if (filtered.isEmpty())
            return null;
        return filtered.get(0);
    }

    public boolean hasRole(String roleName) {
        List<SkyUserRole> matched = getRoles().stream()
                .filter(r -> r.getRole().equals(roleName))
                .collect(Collectors.toList());
        return (!matched.isEmpty());
    }

    public boolean hasRole(String roleName, SkyAdminArea area, int areaId) {
        for (SkyUserRole aRole : getRoles(area, areaId)) {
            if (roleName.equals(aRole.getRole()))
                return true;
        }
        return false;
    }

    public boolean hasRole(String roleName, String areaStr, int areaId) {
        return hasRole(roleName, SkyAdminArea.valueOf(areaStr), areaId);
    }

    *//**
     * Find matching  SkyUserRole for given area and returns it.
     *
     * @param area admin area for which Role object is needed
     * @return matching SkyUserRole object if found, null otherwise.
     *//*
    public List<SkyUserRole> getRoles(SkyAdminArea area) {
        return getRoles().stream()
                .filter(r -> r.getAdminArea() != null && r.getAdminAreaId() != null && r.getAdminArea().equals(area))
                .collect(Collectors.toList());
    }

    public List<SkyUserRole> getRoles(SkyAdminArea area, int areaId) {
        return getRoles().stream()
                .filter(r -> r.getAdminArea() != null
                        && r.getAdminAreaId() != null
                        && r.getAdminArea().equals(area)
                        && (r.getAdminAreaId() == areaId))
                .collect(Collectors.toList());
    }

    *//**
     * Find matching  SkyUserRole for given areaStr and returns it.
     *
     * @param areaStr name of the admin area for which Role object is needed
     * @return matching SkyUserRole object if found, null otherwise.
     * @throws IllegalArgumentException if passed areaStr is NOT a valid Admin Area
     *//*
    public List<SkyUserRole> getRoles(String areaStr) {
        SkyAdminArea area = SkyAdminArea.valueOf(areaStr);
        return getRoles(area);
    }

    public List<SkyUserRole> getRoles(String areaStr, int areaId) {
        SkyAdminArea area = SkyAdminArea.valueOf(areaStr);
        return getRoles(area, areaId);
    }

    public Collection<String> getPermissions(SkyAdminArea area) {
        return getPermissionSet(getRoles(area));
    }

    private Collection<String> getPermissionSet(List<SkyUserRole> roles) {
        if (roles == null || roles.isEmpty())
            return SkyUserRole.blankPermissions;
        Set<String> permissions = new HashSet<>();
        roles.forEach(r -> permissions.addAll(r.getPermissions()));
        return permissions;
    }

    public Collection<String> getPermissions(SkyAdminArea area, int areaId) {
        List<SkyUserRole> matched = getRoles(area, areaId);
        Set<String> permissionSet = new HashSet<>();
        matched.forEach(x -> permissionSet.addAll(x.getPermissions()));
        return permissionSet;
    }

    public Collection<String> getPermissions(String areaStr) {
        SkyAdminArea area = SkyAdminArea.valueOf(areaStr);
        return getPermissions(area);
    }

    public Collection<String> getPermissions(String areaStr, int areaId) {
        SkyAdminArea area = SkyAdminArea.valueOf(areaStr);
        return getPermissions(area, areaId);
    }

    @JsonIgnore
    public Collection<String> getRolesText() {
        return getRoles().stream().map(SkyUserRole::getRole).collect(Collectors.toSet());
    }

    @JsonIgnore
    public Collection<String> getPermissions() {
        Set<String> allPermissions = new HashSet<>();
        getRoles().forEach(r ->
                allPermissions.addAll(r.getPermissions())
        );
        return allPermissions;
    }

    public boolean hasNetworkPermission(int networkId, String permission) {
        return hasPermission(SkyAdminArea.NETWORK, networkId, permission);
    }

    public boolean hasEnterprisePermission(int enterpriseId, String permission) {
        return hasPermission(SkyAdminArea.ENTERPRISE, enterpriseId, permission);
    }

    public boolean hasLocationPermission(int locationId, String permission) {
        return hasPermission(SkyAdminArea.LOCATION, locationId, permission);
    }

    public boolean hasChargerPermission(int chargerId, String permission) {
        return hasPermission(SkyAdminArea.CHARGER, chargerId, permission);
    }

    public boolean hasPermission(SkyAdminArea area, int areaId, String permission) {
        for (SkyUserRole aRole : getRoles()) {
            if (aRole.getAdminArea() == null || !aRole.getAdminArea().equals(area))
                continue;
            if (aRole.getAdminAreaId() == null || !aRole.getAdminAreaId().equals(areaId))
                continue;
            if (aRole.getPermissions().contains(permission))
                return true;
        }
        return false;
    }

    public boolean hasPermission(String areaStr, int areaId, String permission) {
        SkyAdminArea area = SkyAdminArea.valueOf(areaStr);
        return getPermissions(area, areaId).contains(permission);
    }

    // SKY Core Specific methods starts here and goes till end of this class


    public String getFirstname() {
        return firstName;
    }


    public String getLastname() {
        return lastName;
    }
*/

    }



