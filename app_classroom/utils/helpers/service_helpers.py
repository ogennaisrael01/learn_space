def email_service_helper(email_service_method, *service_args, context_updates=None, **service_kwargs):
    """ A helper function for managing email service """
    try:
        # Call the email service method
        subject, context = email_service_method(*service_args, **service_kwargs)
        
        # Update context with provided updates, or return as-is if none provided
        if context_updates:
            context.update(context_updates)
        
        return subject, context
    except (ValueError, TypeError) as e:
        return None, {}
    except Exception as e:
        raise e