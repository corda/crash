/*
 * Copyright (C) 2012 eXo Platform SAS.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */

package org.crsh.cmdline;

import org.crsh.cmdline.spi.ValueCompletion;

import java.io.Serializable;

public final class CommandCompletion implements Serializable {

  /** . */
  private final Delimiter delimiter;

  /** . */
  private final ValueCompletion value;

  public CommandCompletion(Delimiter delimiter, ValueCompletion value) throws NullPointerException {
    if (delimiter == null) {
      throw new NullPointerException("No null delimiter accepted");
    }
    if (value == null) {
      throw new NullPointerException("No null value accepted");
    }

    //
    this.delimiter = delimiter;
    this.value = value;
  }

  public Delimiter getDelimiter() {
    return delimiter;
  }

  public ValueCompletion getValue() {
    return value;
  }

  @Override
  public boolean equals(Object obj) {
    if (obj == this) {
      return true;
    }
    if (obj instanceof CommandCompletion) {
      CommandCompletion that = (CommandCompletion)obj;
      return delimiter.equals(that.delimiter) && value.equals(that.value);
    }
    return false;
  }

  @Override
  public String toString() {
    return "CommandCompletion[delimiter=" + delimiter + ",value=" + value + "]";
  }
}