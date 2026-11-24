package org.springframework.web.bind.annotation;

import java.lang.annotation.*;

// Stand-in for Spring's annotation, so the case compiles with javac alone.
@Retention(RetentionPolicy.RUNTIME) @Target(ElementType.PARAMETER)
public @interface RequestParam { String value() default ""; }
