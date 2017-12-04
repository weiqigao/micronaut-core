/*
 * Copyright 2017 original authors
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License. 
 */
package org.particleframework.context.annotation;

import javax.inject.Singleton;
import java.lang.annotation.Documented;
import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * <p>This annotation allows driving the production of {@link Bean} definitions from either configuration or the presence of another bean definition</p>
 *
 * <p>For example:</p>
 *
 * <pre><code>
 *  {@literal @}EachProperty("foo.bar")
 *   public class ExampleConfiguration {
 *   }
 * </code></pre>
 *
 * <p>In the above example a new {@code ExampleConfiguration} bean will be created for each item under the {@code foo.bar} key in application configuration</p>
 *
 * <p>A reference to the configuration entry name can be obtained with the {@link Argument} annotation applied to a constructor argument:</p>
 *
 * <pre><code>
 *  {@literal @}EachProperty("foo.bar")
 *   public class ExampleConfiguration {
 *      ExampleConfiguration({@literal @}Argument String name) {
 *          ...
 *      }
 *   }
 * </code></pre>
 *
 * <p>In the above example for a configuration property of {@code foo.bar.test}, the value of the {@code name} argument will be {@code "test"}</p>
 *
 * <p>The bean is created as a singleton with a {@link javax.inject.Named} qualifier matching the configuration entry name, thus allowing retrieval with:</p>
 *
 * <pre><code>
 *  ExampleConfiguration exampleConfiguration = applicationContext.getBean(ExampleConfiguration.class, Qualifiers.byName("test"));
 * </code></pre>
 *
 * <p>Or alternatively dependency injection via the {@link javax.inject.Named} qualifier.</p>
 *
 * <p>This annotation is typically used in conjunction with {@link EachBean}. For example, one can drive the configuration of other beans with the {@link EachBean} annotation:</p>
 *
 * <pre><code>
 *  {@literal @}EachBean(ExampleConfiguration)
 *  {@literal @}Singleton
 *   public class ExampleBean {
 *      ExampleBean(ExampleConfiguration config) {
 *          ...
 *      }
 *   }
 * </code></pre>
 *
 * @see EachBean
 * @see ConfigurationProperties
 *
 * @author Graeme Rocher
 * @since 1.0
 */
@Documented
@Retention(RUNTIME)
@Target({ElementType.METHOD, ElementType.TYPE})
@Singleton
@ConfigurationReader
public @interface EachProperty {
    /**
     * @return The property that this bean is driven by
     */
    @AliasFor(annotation = ConfigurationReader.class, member = "value")
    String value();

    /**
     * @return The name of the key returned by {@link #value()} that should be regarded as the {@link Primary} bean
     */
    String primary() default "";
}
