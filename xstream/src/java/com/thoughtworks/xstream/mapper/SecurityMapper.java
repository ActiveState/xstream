/*
 * Copyright (C) 2014 XStream Committers.
 * All rights reserved.
 *
 * Created on 08. January 2014 by Joerg Schaible
 */
package com.thoughtworks.xstream.mapper;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import com.thoughtworks.xstream.converters.ConversionException;
import com.thoughtworks.xstream.security.AnyTypePermission;
import com.thoughtworks.xstream.security.ForbiddenClassException;
import com.thoughtworks.xstream.security.NoTypePermission;
import com.thoughtworks.xstream.security.TypePermission;


/**
 * A Mapper implementation injecting a security layer based on permission rules for any type required in the
 * unmarshalling process.
 * 
 * @author J&ouml;rg Schaible
 * @since 1.4.7
 */
public class SecurityMapper extends MapperWrapper {

    private final List permissions;

    /**
     * Construct a SecurityMapper.
     * 
     * @param wrapped the mapper chain
     * @since 1.4.7
     */
    public SecurityMapper(final Mapper wrapped) {
        this(wrapped, (TypePermission[])null);
    }

    /**
     * Construct a SecurityMapper.
     * 
     * @param wrapped the mapper chain
     * @param permissions the predefined permissions
     * @since 1.4.7
     */
    public SecurityMapper(final Mapper wrapped, final TypePermission[] permissions) {
        super(wrapped);
        this.permissions = permissions == null //
            ? new ArrayList()
            : new ArrayList(Arrays.asList(permissions));
    }

    /**
     * Add a new permission.
     * <p>
     * Permissions are evaluated in the added sequence. An instance of {@link NoTypePermission} or
     * {@link AnyTypePermission} will implicitly wipe any existing permission.
     * </p>
     * 
     * @param permission the permission to add.
     * @since 1.4.7
     */
    public void addPermission(final TypePermission permission) {
        if (permission.equals(NoTypePermission.NONE) || permission.equals(AnyTypePermission.ANY))
            permissions.clear();
        permissions.add(0, permission);
    }

    /**
     * Security blacklist guard checked at the class-name level, before any class is loaded.
     * Blocks known RCE/SSRF gadget-chain classes regardless of the configured TypePermission list.
     *
     * CVE coverage:
     *   CVE-2020-26258 — SSRF via javax.imageio.ImageIO$ContainsFilter
     *
     * Defence-in-depth (also guards the CVE-2013-7285 gadget chain):
     *   java.beans.EventHandler, java.lang.ProcessBuilder
     */
    private static void checkCVE_2020_26258(final String elementName) {
        if ("java.beans.EventHandler".equals(elementName)
                || "java.lang.ProcessBuilder".equals(elementName)) {
            throw new ConversionException(
                "Security violation: class '" + elementName
                + "' is blocked (CVE-2013-7285)");
        }
        if ("javax.imageio.ImageIO$ContainsFilter".equals(elementName)) {
            throw new ConversionException(
                "Security violation: class '" + elementName
                + "' is blocked (CVE-2020-26258)");
        }
    }

    public Class realClass(final String elementName) {
        checkCVE_2020_26258(elementName);
        final Class type = super.realClass(elementName);
        for (int i = 0; i < permissions.size(); ++i) {
            final TypePermission permission = (TypePermission)permissions.get(i);
            if (permission.allows(type))
                return type;
        }
        throw new ForbiddenClassException(type);
    }
}
