package com.prgrms.devcourse.configures;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.EventListener;
import org.springframework.scheduling.annotation.Async;
import org.springframework.security.authentication.event.AbstractAuthenticationFailureEvent;
import org.springframework.security.authentication.event.AuthenticationSuccessEvent;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class CustomAuthenticationEventHandler {

    private final Logger logger = LoggerFactory.getLogger(getClass());

    @Async
    @EventListener
    public void handleAuthenticationSuccessEvent(AuthenticationSuccessEvent event) {
        try {
            Thread.sleep(5000L);
        } catch (InterruptedException e) {
        }

        Authentication authentication = event.getAuthentication();
        logger.info("Successful authentication result: {}", authentication.getPrincipal());

    }

    @EventListener
    public void handleAuthenticationFailureEvent(AbstractAuthenticationFailureEvent event) {
        Exception e = event.getException();
        Authentication authentication = event.getAuthentication();
        logger.warn("Unsuccessful authentication result: {}", authentication, e);
    }

}
