/**

Copyright (c) 2008-2010, The University of Manchester, United Kingdom.
All rights reserved.

Redistribution and use in source and binary forms, with or without 
modification, are permitted provided that the following conditions are met:

 * Redistributions of source code must retain the above copyright notice, 
      this list of conditions and the following disclaimer.
 * Redistributions in binary form must reproduce the above copyright 
      notice, this list of conditions and the following disclaimer in the 
      documentation and/or other materials provided with the distribution.
 * Neither the name of the The University of Manchester nor the names of 
      its contributors may be used to endorse or promote products derived 
      from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" 
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE 
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE 
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE 
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR 
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS 
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN 
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) 
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE 
POSSIBILITY OF SUCH DAMAGE.

  Author........: Bruno Harbulot
 
 */
package uk.ac.manchester.rcs.bruno.vomscertreader;

import java.security.Principal;

/**
 * This is a Principal representing a VOMS attribute.
 * 
 * @author Bruno Harbulot (Bruno.Harbulot@manchester.ac.uk)
 */
public class VomsPrincipal implements Principal {
    private final String group;
    private final String role;
    private final String capability;

    public VomsPrincipal(String group, String role, String capability) {
        this.group = group;
        this.role = role;
        this.capability = capability;
    }

    public String getGroup() {
        return this.group;
    }

    public String getRole() {
        return this.role;
    }

    public String getCapability() {
        return this.capability;
    }

    @Override
    public String getName() {
        StringBuilder sb = new StringBuilder();
        if (this.group != null) {
            sb.append(this.group);
        } else {
            sb.append("/");
        }
        sb.append("/Role=");
        if (this.role != null) {
            sb.append(this.role);
        } else {
            sb.append("NULL");
        }
        sb.append("/Capability=");
        if (this.capability != null) {
            sb.append(this.capability);
        } else {
            sb.append("NULL");
        }
        return sb.toString();
    }

    @Override
    public String toString() {
        return "VOMS Principal: " + getName();
    }
}
